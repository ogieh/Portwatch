"""
Reconnaissance service for PortWatch Pro.

Wraps common Kali Linux recon tools into a single entry point:
  1. Subdomain enumeration   (subfinder, amass, or built-in DNS brute)
  2. DNS record lookup        (dig / nslookup or dnspython)
  3. WHOIS lookup             (whois CLI or python-whois)
  4. Technology fingerprinting (whatweb or wappalyzer-style heuristics)
  5. Email security checks    (SPF, DKIM, DMARC record validation)

Every function has a simulation fallback so the entire recon workflow is
demonstrable without any external tools installed.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import hashlib
import random

SIMULATE = os.environ.get("PORTWATCH_SIMULATE", "").lower() in ("1", "true", "yes")


def _tool_available(name):
    return shutil.which(name) is not None


def _run(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"{cmd[0]} not found", -1
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -2


def _seeded_rng(target):
    seed = int(hashlib.sha256(target.encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)


# ============================================================
# 1. SUBDOMAIN ENUMERATION
# ============================================================

_SIM_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "portal", "vpn", "api",
    "dev", "staging", "test", "cdn", "blog", "shop", "app",
    "ns1", "ns2", "mx", "webmail", "remote", "intranet",
]


def enumerate_subdomains(domain, simulate=None):
    """
    Returns {"domain": str, "subdomains": [str], "tool": str, "count": int}.
    Tries subfinder first, then amass, then built-in DNS brute.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_subdomains(domain)

    if _tool_available("subfinder"):
        out, _, rc = _run(["subfinder", "-d", domain, "-silent"], timeout=60)
        if rc == 0 and out:
            subs = sorted(set(line.strip() for line in out.splitlines() if line.strip()))
            return {"domain": domain, "subdomains": subs, "tool": "subfinder", "count": len(subs)}

    if _tool_available("amass"):
        out, _, rc = _run(["amass", "enum", "-passive", "-d", domain], timeout=120)
        if rc == 0 and out:
            subs = sorted(set(line.strip() for line in out.splitlines() if line.strip()))
            return {"domain": domain, "subdomains": subs, "tool": "amass", "count": len(subs)}

    # Built-in DNS brute
    subs = []
    for prefix in _SIM_SUBDOMAINS:
        fqdn = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            subs.append(fqdn)
        except socket.gaierror:
            pass
    return {"domain": domain, "subdomains": sorted(subs), "tool": "dns-brute", "count": len(subs)}


def _sim_subdomains(domain):
    rng = _seeded_rng(domain)
    count = rng.randint(4, 12)
    chosen = rng.sample(_SIM_SUBDOMAINS, min(count, len(_SIM_SUBDOMAINS)))
    subs = sorted(f"{s}.{domain}" for s in chosen)
    return {"domain": domain, "subdomains": subs, "tool": "simulated", "count": len(subs)}


# ============================================================
# 2. DNS RECORDS
# ============================================================

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def dns_lookup(domain, simulate=None):
    """
    Returns {"domain": str, "records": [{"type": str, "value": str}], "tool": str}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_dns(domain)

    records = []
    if _tool_available("dig"):
        for rtype in _RECORD_TYPES:
            out, _, rc = _run(["dig", "+short", rtype, domain], timeout=10)
            if rc == 0 and out:
                for line in out.splitlines():
                    line = line.strip()
                    if line and not line.startswith(";;"):
                        records.append({"type": rtype, "value": line})
        return {"domain": domain, "records": records, "tool": "dig"}

    # Python fallback
    try:
        for info in socket.getaddrinfo(domain, None):
            addr = info[4][0]
            rtype = "AAAA" if ":" in addr else "A"
            entry = {"type": rtype, "value": addr}
            if entry not in records:
                records.append(entry)
    except socket.gaierror:
        pass
    return {"domain": domain, "records": records, "tool": "socket"}


def _sim_dns(domain):
    rng = _seeded_rng(domain)
    records = [
        {"type": "A", "value": f"{rng.randint(10,200)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"},
        {"type": "MX", "value": f"10 mail.{domain}"},
        {"type": "NS", "value": f"ns1.{domain}"},
        {"type": "NS", "value": f"ns2.{domain}"},
        {"type": "TXT", "value": f'"v=spf1 include:_spf.{domain} ~all"'},
    ]
    if rng.random() < 0.5:
        records.append({"type": "AAAA", "value": f"2001:db8::{rng.randint(1,9999):x}"})
    return {"domain": domain, "records": records, "tool": "simulated"}


# ============================================================
# 3. WHOIS
# ============================================================

def whois_lookup(domain, simulate=None):
    """
    Returns {"domain": str, "raw": str, "parsed": dict, "tool": str}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_whois(domain)

    if _tool_available("whois"):
        out, _, rc = _run(["whois", domain], timeout=15)
        if rc == 0 and out:
            parsed = _parse_whois(out)
            return {"domain": domain, "raw": out, "parsed": parsed, "tool": "whois"}

    return {"domain": domain, "raw": "", "parsed": {}, "tool": "unavailable"}


def _parse_whois(text):
    parsed = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "expiry_date": r"(?:Registry Expiry|Expiration) Date:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
        "dnssec": r"DNSSEC:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            parsed[key] = matches if key == "name_servers" else matches[0].strip()
    return parsed


def _sim_whois(domain):
    rng = _seeded_rng(domain)
    registrars = ["GoDaddy", "Namecheap", "Cloudflare", "Google Domains", "Route53"]
    parsed = {
        "registrar": rng.choice(registrars),
        "creation_date": f"20{rng.randint(10,22)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
        "expiry_date": f"20{rng.randint(25,30)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
        "name_servers": [f"ns1.{domain}", f"ns2.{domain}"],
        "dnssec": rng.choice(["unsigned", "signedDelegation"]),
    }
    return {"domain": domain, "raw": "(simulated)", "parsed": parsed, "tool": "simulated"}


# ============================================================
# 4. TECHNOLOGY FINGERPRINTING
# ============================================================

_TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
    "Joomla": [r"Joomla", r"/media/jui/"],
    "Drupal": [r"Drupal", r"drupal\.js"],
    "nginx": [r"nginx", r"Server:\s*nginx"],
    "Apache": [r"Apache", r"Server:\s*Apache"],
    "jQuery": [r"jquery[\.\-]", r"jQuery"],
    "Bootstrap": [r"bootstrap\.min", r"bootstrap\.css"],
    "React": [r"react\.production", r"__REACT"],
    "PHP": [r"X-Powered-By:\s*PHP", r"\.php"],
    "ASP.NET": [r"X-AspNet-Version", r"X-Powered-By:\s*ASP\.NET"],
    "Cloudflare": [r"cf-ray", r"cloudflare"],
    "Google Analytics": [r"google-analytics\.com", r"gtag"],
}


def detect_technologies(target, simulate=None):
    """
    Returns {"target": str, "technologies": [{"name": str, "confidence": str}], "tool": str}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_tech(target)

    if _tool_available("whatweb"):
        out, _, rc = _run(["whatweb", "-q", "--log-json=-", target], timeout=30)
        if rc == 0 and out:
            techs = []
            try:
                for line in out.splitlines():
                    data = json.loads(line)
                    for plugin, details in data.get("plugins", {}).items():
                        if plugin.lower() not in ("ip", "country", "httpserver"):
                            version = ""
                            if isinstance(details, dict):
                                version = details.get("version", [""])[0] if details.get("version") else ""
                            name = f"{plugin} {version}".strip() if version else plugin
                            techs.append({"name": name, "confidence": "confirmed"})
            except (json.JSONDecodeError, KeyError):
                pass
            if techs:
                return {"target": target, "technologies": techs, "tool": "whatweb"}

    # Python fallback: HTTP header + body pattern matching
    techs = []
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = target if target.startswith("http") else f"http://{target}"
        req = urllib.request.Request(url, headers={"User-Agent": "PortWatch/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            headers = str(resp.headers)
            body = resp.read(65536).decode("utf-8", "replace")
            combined = headers + body
            for tech, patterns in _TECH_SIGNATURES.items():
                for pat in patterns:
                    if re.search(pat, combined, re.IGNORECASE):
                        techs.append({"name": tech, "confidence": "likely"})
                        break
    except Exception:
        pass
    return {"target": target, "technologies": techs, "tool": "http-fingerprint"}


def _sim_tech(target):
    rng = _seeded_rng(target)
    pool = [
        ("nginx 1.18.0", "confirmed"), ("PHP 7.4", "confirmed"),
        ("jQuery 3.6", "likely"), ("WordPress 6.2", "confirmed"),
        ("Bootstrap 5.3", "likely"), ("Google Analytics", "likely"),
        ("Cloudflare", "confirmed"), ("Apache 2.4.52", "confirmed"),
        ("MySQL", "likely"), ("OpenSSL 3.0", "confirmed"),
    ]
    count = rng.randint(3, 6)
    chosen = rng.sample(pool, min(count, len(pool)))
    techs = [{"name": n, "confidence": c} for n, c in chosen]
    return {"target": target, "technologies": techs, "tool": "simulated"}


# ============================================================
# 5. EMAIL SECURITY
# ============================================================

def check_email_security(domain, simulate=None):
    """
    Returns {"domain": str, "spf": dict, "dkim": dict, "dmarc": dict}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_email(domain)

    results = {"domain": domain, "spf": {}, "dkim": {}, "dmarc": {}}

    def _dns_txt(name):
        if _tool_available("dig"):
            out, _, rc = _run(["dig", "+short", "TXT", name], timeout=8)
            if rc == 0:
                return out
        try:
            import dns.resolver
            answers = dns.resolver.resolve(name, "TXT")
            return "\n".join(str(r) for r in answers)
        except Exception:
            pass
        return ""

    # SPF
    spf_raw = _dns_txt(domain)
    spf_record = ""
    for line in spf_raw.splitlines():
        if "v=spf1" in line.lower():
            spf_record = line.strip().strip('"')
            break
    results["spf"] = {
        "exists": bool(spf_record),
        "record": spf_record,
        "has_all": "-all" in spf_record or "~all" in spf_record if spf_record else False,
        "strict": "-all" in spf_record if spf_record else False,
    }

    # DMARC
    dmarc_raw = _dns_txt(f"_dmarc.{domain}")
    dmarc_record = ""
    for line in dmarc_raw.splitlines():
        if "v=dmarc1" in line.lower():
            dmarc_record = line.strip().strip('"')
            break
    policy = ""
    if dmarc_record:
        pm = re.search(r"p=(\w+)", dmarc_record, re.IGNORECASE)
        policy = pm.group(1) if pm else ""
    results["dmarc"] = {
        "exists": bool(dmarc_record),
        "record": dmarc_record,
        "policy": policy,
        "is_enforcing": policy.lower() in ("reject", "quarantine") if policy else False,
    }

    # DKIM (check default selector)
    dkim_raw = _dns_txt(f"default._domainkey.{domain}")
    results["dkim"] = {
        "exists": bool(dkim_raw and "v=dkim" in dkim_raw.lower()),
        "record": dkim_raw.strip().strip('"') if dkim_raw else "",
        "note": "Checked 'default' selector only. Other selectors may exist.",
    }

    return results


def _sim_email(domain):
    rng = _seeded_rng(domain)
    has_spf = rng.random() < 0.7
    has_dmarc = rng.random() < 0.5
    return {
        "domain": domain,
        "spf": {
            "exists": has_spf,
            "record": f"v=spf1 include:_spf.{domain} ~all" if has_spf else "",
            "has_all": has_spf,
            "strict": rng.random() < 0.3 if has_spf else False,
        },
        "dmarc": {
            "exists": has_dmarc,
            "record": f"v=DMARC1; p={rng.choice(['none','quarantine','reject'])}" if has_dmarc else "",
            "policy": rng.choice(["none", "quarantine", "reject"]) if has_dmarc else "",
            "is_enforcing": has_dmarc and rng.random() < 0.4,
        },
        "dkim": {
            "exists": rng.random() < 0.4,
            "record": "",
            "note": "Checked 'default' selector only.",
        },
    }


# ============================================================
# 6. DIRECTORY BRUTEFORCE
# ============================================================

_COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php", "/api", "/api/v1",
    "/.env", "/.git/config", "/robots.txt", "/sitemap.xml", "/backup",
    "/phpmyadmin", "/server-status", "/server-info", "/.htaccess",
    "/config", "/debug", "/test", "/staging", "/console", "/.well-known/security.txt",
    "/swagger", "/docs", "/graphql", "/health", "/status", "/metrics",
]


def directory_bruteforce(target, wordlist=None, simulate=None):
    """
    Returns {"target": str, "found": [{"path": str, "status": int, "size": int}], "tool": str, "total_checked": int}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_dirbrute(target)

    base_url = target if target.startswith("http") else f"http://{target}"

    if _tool_available("gobuster") and wordlist and os.path.isfile(wordlist):
        out, _, rc = _run(
            ["gobuster", "dir", "-u", base_url, "-w", wordlist, "-q", "-t", "10", "--no-error"],
            timeout=120,
        )
        if rc == 0 and out:
            found = []
            for line in out.splitlines():
                m = re.match(r"(\S+)\s+\(Status:\s*(\d+)\)", line)
                if m:
                    found.append({"path": m.group(1), "status": int(m.group(2)), "size": 0})
            return {"target": target, "found": found, "tool": "gobuster", "total_checked": -1}

    # Built-in check
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    found = []
    paths = wordlist if isinstance(wordlist, list) else _COMMON_PATHS
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PortWatch/1.0"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                if resp.getcode() < 400:
                    found.append({"path": path, "status": resp.getcode(), "size": int(resp.headers.get("Content-Length", 0))})
        except Exception:
            pass

    return {"target": target, "found": found, "tool": "built-in", "total_checked": len(paths)}


def _sim_dirbrute(target):
    rng = _seeded_rng(target)
    count = rng.randint(3, 8)
    chosen = rng.sample(_COMMON_PATHS, min(count, len(_COMMON_PATHS)))
    found = []
    for path in sorted(chosen):
        status = rng.choice([200, 200, 200, 301, 403])
        found.append({"path": path, "status": status, "size": rng.randint(200, 15000)})
    return {"target": target, "found": found, "tool": "simulated", "total_checked": len(_COMMON_PATHS)}


# ============================================================
# 7. WAF DETECTION
# ============================================================

def detect_waf(target, simulate=None):
    """
    Returns {"target": str, "waf_detected": bool, "waf_name": str, "tool": str}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_waf(target)

    if _tool_available("wafw00f"):
        out, _, rc = _run(["wafw00f", target, "-o-"], timeout=20)
        if rc == 0 and out:
            if "is behind" in out.lower():
                m = re.search(r"is behind\s+(.+?)(?:\s+WAF|\s*$)", out, re.IGNORECASE)
                waf_name = m.group(1).strip() if m else "Unknown WAF"
                return {"target": target, "waf_detected": True, "waf_name": waf_name, "tool": "wafw00f"}
            if "no waf" in out.lower():
                return {"target": target, "waf_detected": False, "waf_name": "", "tool": "wafw00f"}

    # Simple header-based detection
    waf_headers = {
        "cf-ray": "Cloudflare", "x-sucuri-id": "Sucuri",
        "x-cdn": "CDN/WAF", "server": None,
    }
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = target if target.startswith("http") else f"http://{target}"
        req = urllib.request.Request(url, headers={"User-Agent": "PortWatch/1.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for hdr, name in waf_headers.items():
                if hdr in headers:
                    if name:
                        return {"target": target, "waf_detected": True, "waf_name": name, "tool": "header-check"}
                    server = headers.get("server", "").lower()
                    if "cloudflare" in server:
                        return {"target": target, "waf_detected": True, "waf_name": "Cloudflare", "tool": "header-check"}
    except Exception:
        pass

    return {"target": target, "waf_detected": False, "waf_name": "", "tool": "header-check"}


def _sim_waf(target):
    rng = _seeded_rng(target)
    if rng.random() < 0.4:
        waf = rng.choice(["Cloudflare", "AWS WAF", "Akamai", "Sucuri", "Imperva"])
        return {"target": target, "waf_detected": True, "waf_name": waf, "tool": "simulated"}
    return {"target": target, "waf_detected": False, "waf_name": "", "tool": "simulated"}


# ============================================================
# 8. NETWORK RECON
# ============================================================

def traceroute(target, simulate=None):
    """
    Returns {"target": str, "hops": [{"hop": int, "ip": str, "rtt": str}], "tool": str}.
    """
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_traceroute(target)

    cmd = "traceroute" if _tool_available("traceroute") else "tracert" if _tool_available("tracert") else None
    if cmd:
        out, _, rc = _run([cmd, "-m", "20", target], timeout=60)
        if rc == 0 and out:
            hops = []
            for line in out.splitlines()[1:]:
                m = re.match(r"\s*(\d+)\s+(.+)", line)
                if m:
                    hop_num = int(m.group(1))
                    rest = m.group(2)
                    ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
                    rtt_m = re.search(r"([\d.]+)\s*ms", rest)
                    hops.append({
                        "hop": hop_num,
                        "ip": ip_m.group(1) if ip_m else "*",
                        "rtt": f"{rtt_m.group(1)} ms" if rtt_m else "*",
                    })
            return {"target": target, "hops": hops, "tool": cmd}

    return {"target": target, "hops": [], "tool": "unavailable"}


def _sim_traceroute(target):
    rng = _seeded_rng(target)
    hop_count = rng.randint(8, 16)
    hops = []
    for i in range(1, hop_count + 1):
        if rng.random() < 0.15:
            hops.append({"hop": i, "ip": "*", "rtt": "*"})
        else:
            ip = f"{rng.randint(10,200)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
            rtt = f"{rng.uniform(1, 80):.1f} ms"
            hops.append({"hop": i, "ip": ip, "rtt": rtt})
    return {"target": target, "hops": hops, "tool": "simulated"}


# ============================================================
# FULL RECON RUNNER
# ============================================================

def run_full_recon(target, simulate=None):
    """
    Runs all recon modules and returns a combined result dict.
    """
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    return {
        "target": target,
        "domain": domain,
        "subdomains": enumerate_subdomains(domain, simulate=simulate),
        "dns": dns_lookup(domain, simulate=simulate),
        "whois": whois_lookup(domain, simulate=simulate),
        "technologies": detect_technologies(target, simulate=simulate),
        "email_security": check_email_security(domain, simulate=simulate),
        "directories": directory_bruteforce(target, simulate=simulate),
        "waf": detect_waf(target, simulate=simulate),
        "traceroute": traceroute(domain, simulate=simulate),
    }
