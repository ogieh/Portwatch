"""
Credential & lockout checks for PortWatch.

Opt-in module (never runs unless explicitly requested per scan):
  1. Finds candidate HTTP login endpoints on open web ports.
  2. Submits a handful of deliberately wrong credentials and classifies
     the response pattern: throttled / lockout-or-captcha / delay-based /
     no rate limiting observed.
  3. Summarises DB credential findings produced by opt-in NSE scripts
     (mysql-empty-password etc.) into plain verdicts.

Honesty rules baked in:
  - "none_observed" means "nothing seen within N probes", never "unlimited".
  - Any failure of this module degrades to empty findings; it can never
    invalidate the main scan results.
"""

import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "PortWatch/1.0 (authorized security assessment)"
ATTEMPTS = 5
MAX_ENDPOINTS = 4
REQUEST_TIMEOUT = 8

DEFAULT_LOGIN_PATHS = [
    "/login",
    "/admin",
    "/admin/login",
    "/wp-login.php",
    "/signin",
    "/user/login",
]

PASSWORD_INPUT_RE = re.compile(r"<input[^>]+type=[\"']password[\"']", re.IGNORECASE)
INPUT_NAME_RE = re.compile(r"<input[^>]*>", re.IGNORECASE)
NAME_ATTR_RE = re.compile(r"name=[\"']([^\"']+)[\"']", re.IGNORECASE)
ACTION_ATTR_RE = re.compile(r"<form[^>]+action=[\"']([^\"'#]*)[\"']", re.IGNORECASE)
AUTH_FINDER_URL_RE = re.compile(r"\s(/[^\s|]+)")

LOCKOUT_WORDS = ("locked", "too many", "blocked", "temporarily disabled", "try again")
CAPTCHA_WORDS = ("captcha", "recaptcha", "hcaptcha", "are you human")

# Verdicts surfaced to UI/report/scoring
V_NONE = "none_observed"
V_THROTTLED = "throttled"
V_LOCKOUT = "lockout"
V_CAPTCHA = "captcha"


def _build_opener():
    """Opener that does NOT follow redirects (a redirect after POST is itself
    a signal) and tolerates self-signed certificates on engagement targets."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    no_redirect = _NoRedirect()
    return urllib.request.build_opener(
        no_redirect, urllib.request.HTTPSHandler(context=ctx)
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(url, data=None, opener=None, timeout=REQUEST_TIMEOUT):
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
        },
        method="POST" if data is not None else "GET",
    )
    start = time.monotonic()
    try:
        with (opener or _build_opener()).open(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
            return resp.getcode(), dict(resp.headers), body, (time.monotonic() - start) * 1000
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", "replace")
        return e.code, dict(e.headers), body, (time.monotonic() - start) * 1000


def extract_form_fields(html_text):
    """
    Returns (post_url_or_None, user_field, pass_field) parsed from a login
    form. Purely heuristic -- best effort on real-world markup.
    """
    form_match = ACTION_ATTR_RE.search(html_text)
    action = form_match.group(1) if form_match else ""

    inputs = INPUT_NAME_RE.findall(html_text)
    named = []
    for tag in inputs:
        m = NAME_ATTR_RE.search(tag)
        if m:
            named.append((tag.lower(), m.group(1)))

    pass_field = next((n for t, n in named if "type=\"password\"" in t or "type='password'" in t), None)
    user_field = next(
        (n for t, n in named if any(w in n.lower() for w in ("user", "email", "login", "name"))),
        None
    )
    return action or None, user_field or "username", pass_field or "password"


def discover_login_endpoints(host, open_web_ports, auth_finder_outputs=()):
    """
    Returns up to MAX_ENDPOINTS candidate login URLs. Sources:
      1. Paths listed by the http-auth-finder NSE output (already scanned).
      2. Common default login paths probed for password inputs.
    """
    candidates = []

    for out in auth_finder_outputs:
        for match in AUTH_FINDER_URL_RE.finditer(out or ""):
            candidates.append(match.group(1))

    scheme_ports = sorted(
        open_web_ports, key=lambda p: 0 if p in (443, 8443) else 1
    )
    for port in scheme_ports[:2]:
        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

        known = [c for c in candidates if c.startswith("/")]
        to_probe = (known + DEFAULT_LOGIN_PATHS)[:10]

        for path in to_probe:
            url = base + path
            try:
                status, _, body, _ = _fetch(url)
            except Exception:
                continue
            if status == 200 and PASSWORD_INPUT_RE.search(body):
                if url not in candidates:
                    candidates.append(url)
                break

    return [c for c in dict.fromkeys(candidates) if c.startswith("http")][:MAX_ENDPOINTS]


def classify_rate_limit(status_codes, latencies_ms, bodies):
    """
    Pure function so it is unit-testable. Returns {"verdict", "detail"}.
    Order of precedence: explicit throttle > captcha/lockout words >
    delay-based throttling > nothing observed.
    """
    if 429 in status_codes or any(s in (503,) for s in status_codes):
        return {"verdict": V_THROTTLED, "detail": "Server returned 429/503 during repeated failures."}

    joined = " ".join(bodies or []).lower()
    if any(w in joined for w in CAPTCHA_WORDS):
        return {"verdict": V_CAPTCHA, "detail": "CAPTCHA challenge appeared after repeated failures."}
    if any(w in joined for w in LOCKOUT_WORDS):
        return {"verdict": V_LOCKOUT, "detail": "Lockout-style response after repeated failures."}

    if len(latencies_ms) >= 4:
        first_two = sum(latencies_ms[:2]) / 2
        last_three = sum(latencies_ms[-3:]) / 3
        if first_two > 25 and last_three >= first_two * 3:
            return {
                "verdict": V_THROTTLED,
                "detail": f"Response delays escalated ({first_two:.0f}ms -> {last_three:.0f}ms): delay-based throttling.",
            }

    return {
        "verdict": V_NONE,
        "detail": f"No throttling, lockout or CAPTCHA observed within {len(status_codes)} failed attempts.",
    }


def probe_login_url(url, attempts=ATTEMPTS):
    """Submit deliberately wrong credentials and classify the behaviour."""
    opener = _build_opener()

    try:
        status, _, body, _ = _fetch(url, opener=opener)
        action, user_field, pass_field = extract_form_fields(body or "")
        target = urllib.parse.urljoin(url, action) if action else url
    except Exception as e:
        return {"url": url, "attempts": 0, "verdict": V_NONE,
                "detail": f"Could not probe endpoint: {e}", "status_codes": []}

    statuses, latencies, bodies = [], [], []
    for i in range(attempts):
        creds = urllib.parse.urlencode({
            user_field: f"portwatch_probe_{i}",
            pass_field: f"x{os.urandom(8).hex()}!",
        }).encode()
        try:
            status, _, body, latency = _fetch(target, data=creds, opener=opener)
            statuses.append(status)
            latencies.append(round(latency))
            bodies.append(body)
        except Exception as e:
            statuses.append(0)
            latencies.append(REQUEST_TIMEOUT * 1000)
            bodies.append(str(e))

    verdict = classify_rate_limit(statuses, latencies, bodies)
    return {
        "url": target,
        "attempts": len([s for s in statuses if s]),
        "status_codes": statuses,
        **verdict,
    }


def summarise_db_scripts(ports_out):
    """
    Turn opt-in DB credential script outputs into simple findings:
    {"port", "check", "vulnerable", "detail"}
    """
    findings = []
    for p in ports_out:
        scripts = p.get("scripts") or {}
        for name, out in scripts.items():
            if not isinstance(out, str) or not out:
                continue
            lower = out.lower()

            if name.endswith("-empty-password"):
                vulnerable = "empty password" in lower or "no password" in lower
                findings.append({
                    "port": p.get("port"),
                    "check": name,
                    "vulnerable": vulnerable,
                    "detail": "Account accepts an empty password." if vulnerable
                              else "Empty-password check ran; no empty-password accounts reported.",
                })
            elif name.endswith("-brute"):
                vulnerable = "valid credentials" in lower or ("accounts" in lower and "found" in lower)
                findings.append({
                    "port": p.get("port"),
                    "check": name,
                    "vulnerable": vulnerable,
                    "detail": "Valid credentials discovered." if vulnerable
                              else "Brute check completed; no valid credentials found.",
                })
    return findings


def run_credential_checks(resolved_host, ports_out):
    """
    Entry point called by scanner when the user opted in.
    Never raises -- any internal failure yields partial/empty findings.
    """
    http_findings = []
    db_findings = summarise_db_scripts(ports_out)

    open_web = [p["port"] for p in ports_out if p.get("state") == "open"]
    web_only = [p for p in open_web if p in (80, 443, 8080, 8443)]

    auth_finder_outputs = [
        (p.get("scripts") or {}).get("http-auth-finder", "")
        for p in ports_out
        if isinstance((p.get("scripts") or {}).get("http-auth-finder"), str)
    ]

    if web_only:
        endpoints = discover_login_endpoints(resolved_host, web_only, auth_finder_outputs)
        for url in endpoints:
            try:
                http_findings.append(probe_login_url(url))
            except Exception as e:
                http_findings.append({
                    "url": url, "attempts": 0, "verdict": V_NONE,
                    "detail": f"Probe error: {e}", "status_codes": [],
                })

    return {
        "enabled": True,
        "http_login_findings": http_findings,
        "db_findings": db_findings,
    }
