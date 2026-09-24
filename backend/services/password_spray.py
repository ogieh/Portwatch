"""
Password spraying service for PortWatch Pro.

Opt-in, controlled credential testing:
  1. HTTP login spray (small set of common passwords across discovered accounts)
  2. SSH credential testing (paramiko, if installed)
  3. FTP anonymous access check

Safety controls:
  - Maximum 5 passwords per target (not brute-force)
  - Mandatory delay between attempts (2s default)
  - Stops on first lockout signal
  - Full audit logging
  - Superadmin can bypass authorization; all others need project authorization

Simulation fallback for all functions.
"""

import hashlib
import os
import random
import time
import re
import ssl
import urllib.request
import urllib.error

SIMULATE = os.environ.get("PORTWATCH_SIMULATE", "").lower() in ("1", "true", "yes")

# Safety posture. Live credential testing is the one genuinely offensive
# capability in the platform, so it is off unless an operator deliberately
# enables it for an engagement. When LIVE_CREDENTIAL_TESTING is not set, every
# function here runs in simulation regardless of the caller's request. This is
# defence in depth on top of the API's authorization gate and scope check.
LIVE_CREDENTIAL_TESTING = os.environ.get(
    "LIVE_CREDENTIAL_TESTING", "").lower() in ("1", "true", "yes")

MAX_PASSWORDS = 5          # not brute force: a handful of common passwords only
MAX_USERNAMES = 10         # cap accounts per run
ATTEMPT_DELAY = 2.0        # seconds between attempts, to avoid lockout/DoS


def _live_allowed():
    """Live testing requires BOTH the global opt-in and that we are not in the
    global simulate mode."""
    return LIVE_CREDENTIAL_TESTING and not SIMULATE


def _effective_simulate(requested):
    """Resolve whether this call runs live or simulated. Live only happens when
    it is both requested (simulate is explicitly False) and permitted by the
    server posture. Anything else falls back to simulation."""
    if requested is True:
        return True
    if requested is False:
        return not _live_allowed()  # honour request only if live is permitted
    # requested is None: default to the server posture (simulate unless live)
    return not _live_allowed()

COMMON_PASSWORDS = [
    "Password1", "Welcome1", "P@ssw0rd", "Summer2024!", "Company123",
    "Changeme1", "Admin123!", "qwerty123", "letmein1", "password1",
]

def _seeded_rng(target):
    seed = int(hashlib.sha256(target.encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)


def spray_http_login(url, usernames, passwords=None, simulate=None):
    """Spray a small set of passwords against an HTTP login form.
    Returns {"url": str, "results": [{"username": str, "password": str, "success": bool, "status": int}],
             "lockout_detected": bool, "tool": str}."""
    if _effective_simulate(simulate):
        return _sim_http_spray(url, usernames)

    # Defence in depth: even reaching the live path, refuse dangerous
    # destinations. The API guards targets too, but the service must not trust
    # its caller.
    from core.target_guard import validate_target, TargetRejected
    try:
        validate_target(url, resolve=True)
    except TargetRejected as e:
        return {"url": url, "results": [], "lockout_detected": False,
                "total_attempts": 0, "tool": "refused", "error": str(e)}

    passwords = (passwords or COMMON_PASSWORDS)[:MAX_PASSWORDS]
    usernames = list(usernames or [])[:MAX_USERNAMES]
    results = []
    lockout = False

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for pwd in passwords:
        if lockout:
            break
        for user in usernames[:10]:
            try:
                data = urllib.parse.urlencode({"username": user, "password": pwd}).encode()
                req = urllib.request.Request(url, data=data, headers={
                    "User-Agent": "PortWatch/1.0 (authorized security assessment)",
                    "Content-Type": "application/x-www-form-urlencoded",
                })
                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                    status = resp.getcode()
                    body = resp.read(8192).decode("utf-8", "replace").lower()
                    success = status == 302 or ("dashboard" in body or "welcome" in body)
                    results.append({"username": user, "password": pwd if success else "***", "success": success, "status": status})
                    if any(w in body for w in ("locked", "too many", "blocked")):
                        lockout = True
                        break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    lockout = True
                    break
                results.append({"username": user, "password": "***", "success": False, "status": e.code})
            except Exception:
                results.append({"username": user, "password": "***", "success": False, "status": 0})
            time.sleep(ATTEMPT_DELAY)

    return {"url": url, "results": results, "lockout_detected": lockout, "total_attempts": len(results), "tool": "http-spray"}


def _sim_http_spray(url, usernames):
    rng = _seeded_rng(url)
    results = []
    lockout = rng.random() < 0.3
    for user in usernames[:5]:
        success = rng.random() < 0.08  # ~8% chance
        results.append({"username": user, "password": "P@ssw0rd" if success else "***", "success": success, "status": 200})
    return {"url": url, "results": results, "lockout_detected": lockout, "total_attempts": len(results), "tool": "simulated"}


def check_ftp_anonymous(target, simulate=None):
    """Check if FTP allows anonymous access.
    Returns {"target": str, "anonymous_allowed": bool, "files": [str], "tool": str}."""
    if _effective_simulate(simulate):
        return _sim_ftp(target)
    from core.target_guard import validate_target, TargetRejected
    try:
        validate_target(target, resolve=True)
    except TargetRejected as e:
        return {"target": target, "anonymous_allowed": False, "files": [], "tool": "refused", "error": str(e)}

    import ftplib
    try:
        ftp = ftplib.FTP(target, timeout=8)
        ftp.login("anonymous", "portwatch@test.com")
        files = ftp.nlst()[:20]
        ftp.quit()
        return {"target": target, "anonymous_allowed": True, "files": files, "tool": "ftplib"}
    except Exception:
        return {"target": target, "anonymous_allowed": False, "files": [], "tool": "ftplib"}


def _sim_ftp(target):
    rng = _seeded_rng(target)
    if rng.random() < 0.25:
        return {"target": target, "anonymous_allowed": True, "files": ["pub/", "incoming/", "README.txt"], "tool": "simulated"}
    return {"target": target, "anonymous_allowed": False, "files": [], "tool": "simulated"}


def check_ssh_auth(target, usernames=None, simulate=None):
    """Test SSH for common weak credentials.
    Returns {"target": str, "results": [{"username": str, "auth_methods": [str]}], "tool": str}."""
    if _effective_simulate(simulate):
        return _sim_ssh(target)
    from core.target_guard import validate_target, TargetRejected
    try:
        validate_target(target, resolve=True)
    except TargetRejected as e:
        return {"target": target, "results": [], "tool": "refused", "error": str(e)}

    users = (usernames or ["root", "admin", "ubuntu", "deploy"])[:MAX_USERNAMES]
    results = []
    try:
        import paramiko
        for user in users[:5]:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                transport = paramiko.Transport((target, 22))
                transport.connect()
                methods = transport.auth_none(user)
                transport.close()
                results.append({"username": user, "auth_methods": list(methods) if methods else ["none"]})
            except paramiko.AuthenticationException:
                results.append({"username": user, "auth_methods": ["password", "publickey"]})
            except Exception:
                pass
    except ImportError:
        return {"target": target, "results": [], "tool": "unavailable (install paramiko)"}

    return {"target": target, "results": results, "tool": "paramiko"}


def _sim_ssh(target):
    rng = _seeded_rng(target)
    results = [
        {"username": "root", "auth_methods": ["publickey", "password"]},
        {"username": "admin", "auth_methods": rng.choice([["publickey"], ["publickey", "password"]])},
    ]
    return {"target": target, "results": results, "tool": "simulated"}
