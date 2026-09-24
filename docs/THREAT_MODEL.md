# PortWatch Pro: Threat Model, Responsible Use and Data Handling

PortWatch Pro is a port scanner with a database behind it. Both halves carry
obligations: the scanner can harm third parties if misused, and the database
holds a map of its users' weakest points. This page states the boundaries the
product enforces, the ones it leaves to the operator, and the known limits.

## 1. Intended use and scope

PortWatch Pro is for assessing systems the user owns or has explicit written
permission to test. Port scanning systems without authorisation is unlawful
in most jurisdictions (for example under the Cybercrimes (Prohibition, Prevention, etc.) Act 2015
in Nigeria, the Computer Misuse Act 1990 in the UK, and the Computer Fraud and
Abuse Act in the United States), and is treated as hostile by most network operators regardless of
intent.

Controls in the product:

- Per-scan consent. Every scan request, manual, scheduled or via API key, must
  carry `authorised: true`. The API refuses the scan otherwise (HTTP 403), and
  the consent is stored on the scan row and in the audit log with the
  requester and their IP address.
- Per-project allowlist. A project can carry a list of allowed targets
  (hostnames, IPs, `*.suffix` wildcards). When set, any target outside it is
  refused before anything is queued. This is the recommended way to run
  engagements: the scope agreed with the client becomes the allowlist.
- Schedules created before consent was recorded are disabled by the scheduler
  rather than run.
- Credential and lockout checks are opt-in per scan and per schedule; they
  are never on by default.
- The simulation engine exists so that demonstrations, screenshots, training
  and grading never touch a real host.

What the product does not do: it cannot verify that a user actually holds
permission. The consent checkbox and allowlist make the user's assertion
explicit and attributable; the legal responsibility stays with the user and
the operator.

## 2. Assets and who wants them

| Asset | Why it matters |
|-------|----------------|
| Scan results | A list of a target's open services, versions and known CVEs is a ready-made attack plan |
| Credentials and tokens | Password hashes, refresh tokens, API keys, reset tokens |
| Audit log | Evidence of who scanned what; tampering hides misuse |
| The scanner itself | An authenticated user could point it at targets they are not allowed to scan; an attacker with an account gets a scanning proxy |

Adversaries considered: an anonymous internet user; a registered but
low-privilege user attempting to read other tenants' data; a user with a
stolen token or API key; a malicious or compromised scan target returning
hostile data; an operator error (default secret, HTTP only).

## 3. Threats and mitigations

| Threat | Mitigation | Where |
|--------|------------|-------|
| Credential stuffing / brute force on login | Fixed-window rate limit per client IP (10/min), generic error message, failed attempts audited | `core/ratelimit.py`, `api/auth.py` |
| Account enumeration via password reset | `/forgot` always returns 200 with the same message | `api/auth.py` |
| Stolen access token | Access tokens expire after 1 hour; refresh tokens are opaque, hashed at rest, rotated on every use, revocable; "sign out everywhere" bumps `token_version` which every access token carries | `core/security.py`, `models.RefreshToken` |
| Stolen API key | Keys are shown once, stored as SHA-256, revocable, cannot perform account management, and scans made with them are tagged `trigger=api` | `models.ApiKey`, `require_session` |
| Password reset link leak | 30-minute expiry, single use, hashed at rest; the raw token is only echoed to the caller in development without SMTP | `models.PasswordResetToken` |
| Horizontal privilege escalation (reading another user's scans by guessing IDs) | Every lookup joins the resource to the authenticated user; tests assert 404 for foreign resources | every `api/*.py`, `tests/test_api_flow.py` |
| Scan abuse (using the platform to scan third parties) | Consent gate, allowlists, per-user scan rate limit, audit trail with IP | section 1 |
| Stored XSS via hostile banners or NSE output | All report output is HTML-escaped; the SPA escapes every interpolated value with `UI.esc` | `services/report.py`, `frontend/js/components.js` |
| Clickjacking / MIME sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, JSON responses `Cache-Control: no-store` | `app.py` |
| Cross-origin API use from a hostile page | Production CORS is off unless origins are listed; bearer tokens are not cookies, so CSRF does not apply | `app.py` |
| Resource exhaustion via long scans | Scans run in a bounded pool off the request thread, each with a per-profile ceiling; the user can cancel; nmap's own `--host-timeout` bounds each phase | `services/scan_jobs.py` |
| Hostile target feeding malformed nmap output | python-nmap parsing failures in phase 2/3 are caught; phase 1 results survive; engine errors are recorded on the scan, never raised to the worker | `services/scanner.py`, `services/scan_service.py` |
| Default secret in production | The app refuses to start with the development secret when `PORTWATCH_ENV=production` | `core/config.py` |
| Container compromise | Runs as an unprivileged user; raw-socket capability only when SYN scans are enabled | `docker/Dockerfile` |
| Audit log tampering | No update or delete route exists; rows survive user deletion (nullable FK) | `services/audit.py` |

## 4. Data handling

- Passwords: scrypt via Werkzeug. Never logged.
- Tokens and API keys: SHA-256 at rest. The raw value exists only in the
  response that created it.
- Scan results: stored as JSON in the operator's database, scoped to the
  owning user. They are the product's value and its liability; back them up
  encrypted and restrict database access to the application user.
- Audit log: retains actor email and client IP indefinitely. Operators subject
  to data-protection law should define a retention period and prune with a
  scheduled `DELETE ... WHERE created_at < ...`; the application intentionally
  provides no UI for this.
- Notifications: webhook and email alerts contain the target, grade and CVE
  list. Send them only to channels the team controls.
- Nothing leaves the deployment except the scans themselves, configured
  webhooks, and SMTP. There is no telemetry and no external vulnerability API;
  the CVE knowledge base is local.

## 5. Known limitations

- The consent checkbox is an attestation, not proof of authorisation.
- Rate limiting and the scan queue are per process. Behind a load balancer
  with several application processes they would be per instance; see
  DEPLOYMENT.md for the Redis-backed path.
- Cancelling a scan stops it at the next phase boundary; a phase already
  inside nmap runs to nmap's own host timeout before the cancel takes effect.
  A timed-out scan is marked failed and its late result discarded, but the
  nmap process finishes on its own.
- The CVE knowledge base is curated and version-string based; a "likely"
  finding is an inference from a banner, which is why every finding carries a
  confidence level. Confirmed findings come only from NSE script output.
- No multi-tenant organisations or roles beyond admin/analyst. Sharing a
  project means sharing an account, which is a reason to add teams before
  selling to more than one company.
- The credential/lockout tester sends real login attempts to the target. It is
  opt-in precisely because that can lock out real accounts; use it only inside
  an agreed scope.

## 6. Responsible-use statement for users

By running a scan you confirm that you own the target or hold explicit written
permission from its owner to test it, that the scan is within the agreed scope
and time window, and that you accept responsibility for the traffic PortWatch
Pro generates on your behalf. Every scan is attributed to your account and
address in the audit log.
