"""
Web vulnerability scanning service for PortWatch Pro.

Active web application testing:
  1. Nikto integration (general web vuln scanner)
  2. CORS misconfiguration testing
  3. Cookie security analysis
  4. Subdomain takeover detection
  5. CMS-specific scanning (wpscan, joomscan)

These are opt-in active tests. Every function has simulation fallback.
"""

import hashlib
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import urllib.request
import urllib.error

SIMULATE = os.environ.get("PORTWATCH_SIMULATE", "").lower() in ("1", "true", "yes")

def _seeded_rng(target):
    seed = int(hashlib.sha256(target.encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)

def _tool_available(name):
    return shutil.which(name) is not None

def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "", "", -1

def _fetch(url, headers=None, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": "PortWatch/1.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.getcode(), dict(resp.headers), resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(65536).decode("utf-8", "replace")
    except Exception:
        return 0, {}, ""


# ============================================================
# 1. NIKTO
# ============================================================

def run_nikto(target, simulate=None):
    """Run Nikto web vulnerability scanner.
    Returns {"target": str, "findings": [{"id": str, "description": str, "url": str, "method": str}], "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_nikto(target)

    if not _tool_available("nikto"):
        return {"target": target, "findings": [], "tool": "unavailable (install nikto)"}

    url = target if target.startswith("http") else f"http://{target}"
    out, _, rc = _run(["nikto", "-h", url, "-Format", "json", "-output", "-"], timeout=180)
    if rc == 0 and out:
        findings = []
        try:
            data = json.loads(out)
            for vuln in data.get("vulnerabilities", []):
                findings.append({
                    "id": vuln.get("id", ""),
                    "description": vuln.get("msg", ""),
                    "url": vuln.get("url", ""),
                    "method": vuln.get("method", "GET"),
                })
        except json.JSONDecodeError:
            for line in out.splitlines():
                if "+ " in line:
                    findings.append({"id": "", "description": line.strip("+ "), "url": "", "method": ""})
        return {"target": target, "findings": findings, "tool": "nikto"}

    return {"target": target, "findings": [], "tool": "nikto (failed)"}


def _sim_nikto(target):
    rng = _seeded_rng(target)
    pool = [
        {"id": "999103", "description": "X-Frame-Options header not set", "method": "GET"},
        {"id": "999986", "description": "Server banner discloses version information", "method": "GET"},
        {"id": "999102", "description": "X-Content-Type-Options header not set", "method": "GET"},
        {"id": "006586", "description": "/phpinfo.php: Output from phpinfo() function found", "method": "GET"},
        {"id": "003268", "description": "/admin/: Admin login page found", "method": "GET"},
        {"id": "003587", "description": "/.env: Environment file found containing potential credentials", "method": "GET"},
        {"id": "006578", "description": "/server-status: Apache server-status page found", "method": "GET"},
        {"id": "003456", "description": "OPTIONS method returns allowed methods including PUT", "method": "OPTIONS"},
    ]
    count = rng.randint(2, 6)
    findings = rng.sample(pool, min(count, len(pool)))
    for f in findings:
        f["url"] = f"http://{target}" + f.get("url", "/")
    return {"target": target, "findings": findings, "tool": "simulated"}


# ============================================================
# 2. CORS MISCONFIGURATION
# ============================================================

def test_cors(target, simulate=None):
    """Test for CORS misconfigurations.
    Returns {"target": str, "findings": [{"test": str, "vulnerable": bool, "detail": str}], "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_cors(target)

    url = target if target.startswith("http") else f"http://{target}"
    findings = []
    tests = [
        ("arbitrary-origin", "https://evil.com"),
        ("null-origin", "null"),
        ("subdomain-wildcard", f"https://attacker.{target.replace('http://','').replace('https://','').split('/')[0]}"),
    ]
    for test_name, origin in tests:
        _, headers, _ = _fetch(url, headers={"Origin": origin})
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        vulnerable = False
        detail = "Not vulnerable"
        if acao == "*":
            vulnerable = True
            detail = "Wildcard origin (*) allowed. Any site can read responses."
        elif acao == origin and origin != "null":
            vulnerable = True
            detail = f"Server reflects arbitrary origin '{origin}'"
            if acac.lower() == "true":
                detail += " WITH credentials. Critical: cookies and auth headers are exposed."
        elif acao == "null" and test_name == "null-origin":
            vulnerable = True
            detail = "Null origin accepted. Sandboxed iframes can read responses."
        findings.append({"test": test_name, "origin_sent": origin, "vulnerable": vulnerable, "detail": detail})

    return {"target": target, "findings": findings, "tool": "http-probe"}


def _sim_cors(target):
    rng = _seeded_rng(target)
    findings = [
        {"test": "arbitrary-origin", "origin_sent": "https://evil.com",
         "vulnerable": rng.random() < 0.3,
         "detail": "Server reflects arbitrary origin" if rng.random() < 0.3 else "Not vulnerable"},
        {"test": "null-origin", "origin_sent": "null",
         "vulnerable": rng.random() < 0.2,
         "detail": "Null origin accepted" if rng.random() < 0.2 else "Not vulnerable"},
    ]
    return {"target": target, "findings": findings, "tool": "simulated"}


# ============================================================
# 3. COOKIE SECURITY
# ============================================================

def analyze_cookies(target, simulate=None):
    """Analyze cookie security flags.
    Returns {"target": str, "cookies": [{"name": str, "flags": dict, "issues": [str]}], "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_cookies(target)

    url = target if target.startswith("http") else f"http://{target}"
    _, headers, _ = _fetch(url)
    cookies = []
    for key in ("Set-Cookie", "set-cookie"):
        for value in headers.get(key, "").split(","):
            if not value.strip():
                continue
            parts = [p.strip() for p in value.split(";")]
            name = parts[0].split("=")[0] if parts else "unknown"
            flags_lower = [p.lower() for p in parts[1:]]
            has_secure = any("secure" in f for f in flags_lower)
            has_httponly = any("httponly" in f for f in flags_lower)
            has_samesite = any("samesite" in f for f in flags_lower)
            issues = []
            if not has_secure:
                issues.append("Missing Secure flag: cookie sent over HTTP")
            if not has_httponly:
                issues.append("Missing HttpOnly flag: accessible to JavaScript (XSS risk)")
            if not has_samesite:
                issues.append("Missing SameSite flag: vulnerable to CSRF")
            cookies.append({
                "name": name,
                "flags": {"secure": has_secure, "httponly": has_httponly, "samesite": has_samesite},
                "issues": issues,
            })
    return {"target": target, "cookies": cookies, "tool": "http-probe"}


def _sim_cookies(target):
    rng = _seeded_rng(target)
    cookies = [
        {"name": "session_id", "flags": {"secure": rng.random()>.4, "httponly": rng.random()>.3, "samesite": rng.random()>.5},
         "issues": []},
        {"name": "_ga", "flags": {"secure": False, "httponly": False, "samesite": False},
         "issues": ["Missing Secure", "Missing HttpOnly", "Missing SameSite"]},
    ]
    return {"target": target, "cookies": cookies, "tool": "simulated"}


# ============================================================
# 4. SUBDOMAIN TAKEOVER DETECTION
# ============================================================

TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "no-such-app",
    "ghost.io": "Site not found",
    "azurewebsites.net": "404 Web Site not found",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "tumblr.com": "There's nothing here",
    "wordpress.com": "Do you want to register",
    "github.io": "There isn't a GitHub Pages site here",
}


def check_subdomain_takeover(subdomains, simulate=None):
    """Check a list of subdomains for potential takeover.
    Returns {"checked": int, "vulnerable": [{"subdomain": str, "cname": str, "provider": str}]}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_takeover(subdomains)

    import socket
    vulnerable = []
    for sub in subdomains[:50]:  # limit
        try:
            _, _, body = _fetch(f"http://{sub}", timeout=5)
            for provider, signature in TAKEOVER_SIGNATURES.items():
                if signature.lower() in body.lower():
                    vulnerable.append({"subdomain": sub, "cname": "", "provider": provider})
                    break
        except Exception:
            pass
    return {"checked": min(len(subdomains), 50), "vulnerable": vulnerable, "tool": "http-probe"}


def _sim_takeover(subdomains):
    rng = _seeded_rng(",".join(subdomains[:5]))
    vuln = []
    if rng.random() < 0.3 and subdomains:
        target = rng.choice(subdomains)
        vuln.append({"subdomain": target, "cname": "old-app.herokuapp.com", "provider": "herokuapp.com"})
    return {"checked": len(subdomains), "vulnerable": vuln, "tool": "simulated"}


# ============================================================
# 5. CMS SCANNING
# ============================================================

def scan_cms(target, cms_type=None, simulate=None):
    """Run CMS-specific vulnerability scanner.
    Returns {"target": str, "cms": str, "findings": [...], "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_cms(target, cms_type)

    if cms_type == "wordpress" and _tool_available("wpscan"):
        out, _, rc = _run(["wpscan", "--url", target, "--format", "json", "--no-banner"], timeout=180)
        if rc == 0 and out:
            findings = []
            try:
                data = json.loads(out)
                for vuln in data.get("interesting_findings", []):
                    findings.append({"type": vuln.get("type", ""), "description": vuln.get("to_s", ""), "url": vuln.get("url", "")})
            except json.JSONDecodeError:
                pass
            return {"target": target, "cms": "wordpress", "findings": findings, "tool": "wpscan"}

    if cms_type == "joomla" and _tool_available("joomscan"):
        out, _, rc = _run(["joomscan", "-u", target], timeout=180)
        if rc == 0 and out:
            findings = []
            for line in out.splitlines():
                if "[++]" in line or "[!]" in line:
                    findings.append({"type": "finding", "description": line.strip(), "url": ""})
            return {"target": target, "cms": "joomla", "findings": findings, "tool": "joomscan"}

    return {"target": target, "cms": cms_type or "unknown", "findings": [], "tool": "unavailable"}


def _sim_cms(target, cms_type):
    rng = _seeded_rng(target)
    cms = cms_type or rng.choice(["wordpress", "joomla"])
    pool = [
        {"type": "vulnerability", "description": "WordPress version 6.2 identified (outdated)", "url": "/readme.html"},
        {"type": "vulnerability", "description": "XML-RPC interface enabled (brute-force risk)", "url": "/xmlrpc.php"},
        {"type": "info", "description": "Default admin login page found", "url": "/wp-admin/"},
        {"type": "vulnerability", "description": "Directory listing enabled on /wp-content/uploads/", "url": "/wp-content/uploads/"},
    ]
    count = rng.randint(1, 3)
    return {"target": target, "cms": cms, "findings": rng.sample(pool, min(count, len(pool))), "tool": "simulated"}


# ============================================================
# COMBINED WEB VULN SCAN
# ============================================================

def run_web_vulns(target, subdomains=None, cms_type=None, simulate=None):
    """Run all web vulnerability modules."""
    return {
        "target": target,
        "nikto": run_nikto(target, simulate=simulate),
        "cors": test_cors(target, simulate=simulate),
        "cookies": analyze_cookies(target, simulate=simulate),
        "subdomain_takeover": check_subdomain_takeover(subdomains or [], simulate=simulate),
        "cms": scan_cms(target, cms_type=cms_type, simulate=simulate),
    }
