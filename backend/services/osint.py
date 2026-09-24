"""
OSINT (Open Source Intelligence) service for PortWatch Pro.

Passive reconnaissance that never touches the target directly:
  1. Certificate transparency log search (crt.sh)
  2. Google dork generation
  3. Email harvesting (theHarvester wrapper)
  4. GitHub leak detection patterns
  5. Breach credential check (HIBP API)

Every function has a simulation fallback.
"""

import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import urllib.request
import urllib.error
import ssl

SIMULATE = os.environ.get("PORTWATCH_SIMULATE", "").lower() in ("1", "true", "yes")

def _seeded_rng(target):
    seed = int(hashlib.sha256(target.encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)

def _tool_available(name):
    return shutil.which(name) is not None

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "", "", -1


# ============================================================
# 1. CERTIFICATE TRANSPARENCY (crt.sh)
# ============================================================

def crt_sh_search(domain, simulate=None):
    """Query crt.sh for all certificates issued for a domain.
    Returns {"domain": str, "subdomains": [str], "certificates": int, "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_crtsh(domain)

    try:
        ctx = ssl.create_default_context()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "PortWatch/1.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        names = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and name.endswith(f".{domain}"):
                    names.add(name)
        return {
            "domain": domain,
            "subdomains": sorted(names),
            "certificates": len(data),
            "tool": "crt.sh",
        }
    except Exception:
        return {"domain": domain, "subdomains": [], "certificates": 0, "tool": "crt.sh (failed)"}


def _sim_crtsh(domain):
    rng = _seeded_rng(domain)
    prefixes = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn",
                "cdn", "blog", "shop", "app", "portal", "secure", "test",
                "autodiscover", "webmail", "remote", "sso", "auth"]
    count = rng.randint(6, 16)
    chosen = rng.sample(prefixes, min(count, len(prefixes)))
    subs = sorted(f"{p}.{domain}" for p in chosen)
    return {"domain": domain, "subdomains": subs, "certificates": rng.randint(20, 200), "tool": "simulated"}


# ============================================================
# 2. GOOGLE DORK GENERATION
# ============================================================

def generate_dorks(domain):
    """Generate Google dork queries for a target domain.
    Returns {"domain": str, "dorks": [{"category": str, "query": str, "description": str}]}."""
    dorks = [
        {"category": "Exposed files", "query": f'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:ppt', "description": "Public documents that may contain metadata or sensitive information"},
        {"category": "Exposed files", "query": f'site:{domain} filetype:sql OR filetype:bak OR filetype:log', "description": "Database dumps, backups, and log files"},
        {"category": "Exposed files", "query": f'site:{domain} filetype:env OR filetype:yml OR filetype:conf', "description": "Configuration files that may contain credentials"},
        {"category": "Login pages", "query": f'site:{domain} inurl:login OR inurl:signin OR inurl:admin', "description": "Administrative and login interfaces"},
        {"category": "Login pages", "query": f'site:{domain} intitle:"index of"', "description": "Open directory listings"},
        {"category": "Error pages", "query": f'site:{domain} intext:"sql syntax" OR intext:"mysql_fetch" OR intext:"ORA-"', "description": "Database error messages indicating potential SQL injection"},
        {"category": "Error pages", "query": f'site:{domain} intext:"Warning:" intext:"on line"', "description": "PHP error messages revealing file paths"},
        {"category": "Sensitive info", "query": f'site:{domain} intext:"password" filetype:txt OR filetype:log', "description": "Files potentially containing credentials"},
        {"category": "Sensitive info", "query": f'site:{domain} inurl:wp-content OR inurl:wp-includes', "description": "WordPress installation paths"},
        {"category": "Subdomains", "query": f'site:*.{domain} -site:www.{domain}', "description": "Indexed subdomains excluding www"},
        {"category": "API endpoints", "query": f'site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql', "description": "Public API endpoints"},
        {"category": "Code leaks", "query": f'"{domain}" site:github.com OR site:gitlab.com OR site:pastebin.com', "description": "Domain mentioned in public code repositories or paste sites"},
    ]
    return {"domain": domain, "dorks": dorks}


# ============================================================
# 3. EMAIL HARVESTING
# ============================================================

def harvest_emails(domain, simulate=None):
    """Find email addresses associated with a domain.
    Returns {"domain": str, "emails": [str], "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_emails(domain)

    if _tool_available("theHarvester"):
        out, _, rc = _run(["theHarvester", "-d", domain, "-b", "all", "-l", "100"], timeout=120)
        if rc == 0 and out:
            emails = sorted(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', out)))
            return {"domain": domain, "emails": emails, "tool": "theHarvester"}

    # Fallback: check common patterns
    emails = []
    prefixes = ["info", "admin", "contact", "support", "hello", "sales"]
    for prefix in prefixes:
        emails.append(f"{prefix}@{domain}")

    return {"domain": domain, "emails": emails, "tool": "common-patterns (install theHarvester for real results)"}


def _sim_emails(domain):
    rng = _seeded_rng(domain)
    names = ["admin", "info", "support", "contact", "sales", "hr", "it",
             "john.doe", "jane.smith", "dev", "security", "ops"]
    count = rng.randint(3, 8)
    chosen = rng.sample(names, min(count, len(names)))
    return {"domain": domain, "emails": sorted(f"{n}@{domain}" for n in chosen), "tool": "simulated"}


# ============================================================
# 4. GITHUB LEAK PATTERNS
# ============================================================

def github_dork_queries(domain):
    """Generate GitHub search queries to find leaked secrets.
    Returns {"domain": str, "queries": [{"query": str, "description": str}]}."""
    queries = [
        {"query": f'"{domain}" password', "description": "Passwords associated with the domain"},
        {"query": f'"{domain}" api_key OR apikey OR api-key', "description": "API keys mentioning the domain"},
        {"query": f'"{domain}" secret_key OR secret OR token', "description": "Secrets and tokens"},
        {"query": f'"{domain}" filename:.env', "description": "Environment files with domain references"},
        {"query": f'"{domain}" filename:docker-compose', "description": "Docker configurations"},
        {"query": f'"{domain}" filename:config extension:yml OR extension:json', "description": "Configuration files"},
        {"query": f'"{domain}" AWS_ACCESS_KEY OR aws_secret', "description": "AWS credentials"},
        {"query": f'"{domain}" jdbc OR mysql OR postgres OR mongodb connection', "description": "Database connection strings"},
    ]
    return {"domain": domain, "queries": queries}


# ============================================================
# 5. BREACH CHECK (HIBP-style)
# ============================================================

def check_breaches(domain, simulate=None):
    """Check if a domain has been in known breaches.
    Returns {"domain": str, "breaches": [{"name": str, "date": str, "records": int}], "tool": str}."""
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_breaches(domain)

    # HIBP API requires an API key for domain search
    # This is a placeholder for the real integration
    return {
        "domain": domain,
        "breaches": [],
        "tool": "unavailable (requires HIBP API key in PORTWATCH_HIBP_KEY)",
    }


def _sim_breaches(domain):
    rng = _seeded_rng(domain)
    breaches = [
        {"name": "Collection #1", "date": "2019-01-17", "records": rng.randint(1000, 50000)},
        {"name": "LinkedIn 2012", "date": "2012-05-05", "records": rng.randint(100, 5000)},
    ] if rng.random() < 0.5 else []
    return {"domain": domain, "breaches": breaches, "tool": "simulated"}


# ============================================================
# COMBINED OSINT
# ============================================================

def run_osint(domain, simulate=None):
    """Run all passive OSINT modules."""
    return {
        "domain": domain,
        "crt_sh": crt_sh_search(domain, simulate=simulate),
        "dorks": generate_dorks(domain),
        "emails": harvest_emails(domain, simulate=simulate),
        "github_dorks": github_dork_queries(domain),
        "breaches": check_breaches(domain, simulate=simulate),
    }
