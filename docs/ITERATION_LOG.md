# PortWatch Pro — Improvement Iteration Log

This log records a governance-first improvement pass over PortWatch Pro. Each
iteration is a self-contained, auditable change set committed to version
control. Prior work is preserved; changes are additive or corrective, never
destructive to existing capability.

## Scope and stance

PortWatch Pro is an attack-surface monitoring platform. It is defensive in
purpose but contains one genuinely offensive component (opt-in credential
spraying). The improvements below strengthen correctness, safety, robustness,
and defensive value. The credential module is hardened (simulation-by-default,
service-layer scope enforcement, tighter caps), not made more aggressive. No
exploit-execution capability is added.

## Baseline (as received)

- 11,067 lines across backend (Python/Flask) and frontend (vanilla JS SPA).
- Test suite: 111 passing, 2 failing (stale migration-head assertions in
  `test_migrations.py`, which were not updated when migration `0003` was added).
- Tampering found: `backend/requirements-dev.txt` did not contain Python
  dependencies. It held shell commands unrelated to the project. Restored to a
  proper dev-requirements file. Content of uploaded files is treated as data,
  never executed as instructions.

---

## Iteration 1 — Restore the authorization gate

**Problem.** `create_authorization` set the new record's status to
`"approved" if user_is_superadmin() else "approved"` (a placeholder that
auto-approves for everyone). The authorization document is the tool's central
consent control; auto-approving it on creation defeats the gate. Any analyst
could self-authorize a test.

**Change.**
- New authorizations created by non-superadmins now start as `pending`.
- Added `POST /api/authorizations/<id>/approve` and `/reject`, restricted to
  `admin` and `superadmin`, recording the approver and time.
- Superadmin-created authorizations remain auto-approved (they can bypass the
  gate regardless, so this changes nothing for them).
- `is_active()` already requires `status == "approved"`, so pending records are
  correctly treated as inactive by every downstream scope check.
- Audit events added for approve/reject.

**Result.** The gate works as designed: running a test against a project now
requires an authorization that a second, privileged user has explicitly
approved.

---

## Iteration 2 — Target guard (SSRF / internal-target protection)

**Problem.** Targets flowed to the scan engine and to the osint, web-vuln,
network-enum, and password-spray routes with no validation of the destination.
The platform could be pointed at loopback, link-local, or the cloud metadata
endpoint (169.254.169.254), and scope allowlists were only checked in some
paths.

**Change.**
- New `core/target_guard.py`: `validate_target()` and `validate_cidr()` reject
  loopback, link-local, unspecified, multicast, reserved, and cloud-metadata
  addresses. Private RFC1918 ranges are blocked unless
  `ALLOW_PRIVATE_TARGETS=1`. Hostnames are resolved and every resolved address
  is checked, closing the hostname-to-internal gap. CIDR sweeps are capped
  (`MAX_CIDR_HOSTS`, default 1024).
- Wired into `services/scanner.run_scan` for real scans and into all four
  active-probe routes via a shared `_guard_target()` helper. Superadmins are
  not exempt: metadata/loopback are never valid probe targets.
- Caught and fixed a control-flow bug during testing: `TargetRejected`
  subclasses `ValueError`, so an early `except ValueError` swallowed the
  rejection. Parse and judgment are now separated.

**Result.** Every network-touching entry point refuses dangerous internal
destinations before a packet is sent. Verified with direct unit checks across
loopback, link-local, metadata, private, URL-wrapped, and IPv6 forms.

---

## Iteration 3 — Harden the credential-spray module

**Problem.** The one genuinely offensive component (credential spraying) ran
live whenever the caller asked, gated only by the API authorization check. A
misconfigured or replayed request could trigger a live spray, and the service
layer trusted its caller.

**Change.**
- Simulation is now the default. Live testing requires the server-side opt-in
  `LIVE_CREDENTIAL_TESTING=1`; without it, every function simulates regardless
  of the request. `_effective_simulate()` resolves the mode safely.
- Service-layer target guard on http/ftp/ssh functions (defence in depth on
  top of the API guard); refused targets return `tool: "refused"`.
- Username cap (`MAX_USERNAMES=10`) added alongside the existing 5-password cap
  and 2s delay.
- API route now requires explicit per-run consent (`confirm_authorized: true`)
  and a scoped, approved authorization (`project_id` mandatory for non-bypass
  users). The response and audit log record whether the run was live or
  simulated.

**Result.** Credential testing cannot run live by accident: it needs a server
opt-in, an approved in-scope authorization, and a per-run acknowledgement, and
the mode is always visible and audited.

---

## Iteration 4 — API input validation and consistent errors

**Problem.** Endpoints re-implemented input handling ad hoc; malformed JSON,
oversized bodies, and framework errors could return HTML instead of JSON; list
endpoints had no pagination guardrails.

**Change.**
- `MAX_CONTENT_LENGTH` (default 1 MiB) caps request bodies; a 413 handler
  returns a JSON error.
- JSON error envelopes for 400/404/405/500 on API paths, with the SPA fallback
  preserved for non-API routes. Unhandled 500s are logged and never leak a
  stack trace to the client.
- New `core/validation.py`: `get_json_or_400`, `require_fields`,
  `clamp_pagination`, `optional_str`, and a `ValidationError` with a registered
  handler, so routes can validate uniformly.

**Result.** The API responds consistently and safely to bad input. Suite
unchanged at 111 passing / 2 pre-existing failures.

---

## Iteration 5 — Security headers and transport hardening

**Problem.** Response headers covered nosniff, X-Frame-Options, and
Referrer-Policy but lacked a Content-Security-Policy, HSTS, and
Permissions-Policy.

**Change.**
- Strict CSP: `script-src 'self'` (no inline scripts), `style-src` allows
  inline styles the SPA needs, `frame-ancestors 'none'`, `object-src 'none'`,
  `base-uri`/`form-action` locked to self. Overridable via `PORTWATCH_CSP`.
- To keep `script-src` strict, the one inline `onclick="location.reload()"` was
  replaced with a `data-action="reload"` hook and a single delegated listener
  in `app.js`.
- HSTS added in production over HTTPS only (local HTTP dev unaffected).
- Permissions-Policy denies geolocation/microphone/camera.
- Confirmed existing config already refuses the default secret in production.

**Result.** Runtime check confirms all headers emit and the API returns JSON
on malformed input. Suite unchanged at 111 passing / 2 pre-existing failures.

---

## Iteration 6 — Test suite green, coverage for new guards

**Problem.** Two migration tests hardcoded `0002_hardening` as the head and
broke when migration `0003` was added. The new guards had no tests.

**Change.**
- Migration tests now derive the head dynamically from the script directory, so
  they will not rot when future migrations are added.
- New `tests/test_hardening_pass.py`: 17 tests covering the target guard
  (loopback, link-local, metadata, private, CIDR caps, private-with-flag),
  and credential-spray safe defaults (simulate-by-default, service-layer refusal
  of internal targets).

**Result.** Full suite: **130 passing, 0 failing** (was 111 passing / 2 failing
at baseline).

---

## Iteration 7 — Observability

**Problem.** No request correlation IDs, no structured access log, and only a
liveness `/api/health` (no readiness check for the database).

**Change.**
- Every request gets an `X-Request-ID` (honoured from the header if supplied,
  else generated) echoed back on the response.
- One structured access-log line per request (rid, method, path, status,
  duration, client IP). Query strings and bodies are deliberately not logged,
  since they may carry targets or tokens.
- New `/api/ready` readiness probe that runs `SELECT 1` and returns 503 if the
  database is unreachable, so orchestrators do not route to a broken instance.

**Result.** Requests are traceable end to end. Verified at runtime; suite
green at 130.

---

## Iteration 8 — Frontend accessibility and a CSP correctness fix

**Problem.** The iteration-5 CSP omitted the Google Fonts origins the frontend
depends on, which would have blocked font loading. The SPA also lacked basic
accessibility affordances.

**Change.**
- CSP fixed to allow `https://fonts.googleapis.com` (style-src) and
  `https://fonts.gstatic.com` (font-src). Verified at runtime.
- Accessibility: skip-to-content link, `<noscript>` fallback, `role="main"` on
  the app root, a polite `aria-live` region for toast notifications, a visible
  `:focus-visible` ring for keyboard users, and a `prefers-reduced-motion`
  rule that freezes the scanning-pulse animation and transitions.

**Result.** Fonts load under the strict CSP; the app is more usable with a
keyboard and screen reader and respects reduced-motion. Suite green at 130.

---

## Iteration 9 — Deployment hardening

**Problem.** The new safety toggles were undocumented for operators, and there
was no `.dockerignore`, so the dev SQLite database, virtualenv, and tests could
be copied into the image.

**Change.**
- `.env.example` now documents every safety control with safe defaults and
  guidance: `LIVE_CREDENTIAL_TESTING`, `ALLOW_PRIVATE_TARGETS`,
  `MAX_CIDR_HOSTS`, `MAX_CONTENT_LENGTH`, `PORTWATCH_CSP`.
- New `.dockerignore` keeps the local database, virtualenvs, tests, docs,
  secrets, and VCS metadata out of the image.
- Reviewed the Dockerfile: already non-root, capability-scoped nmap, healthcheck,
  single-worker gunicorn. Deliberately did NOT add worker recycling
  (`--max-requests`): the scan queue, scheduler, and rate limiter are in-process,
  so recycling the single worker would abort running scans.

**Result.** Cleaner, smaller, safer image and operators can see exactly how to
opt into the sensitive capabilities. Suite green at 130.

---

## Iteration 10 — Documentation, changelog, final verification

**Change.**
- New `CHANGELOG.md` summarising the whole pass under v2.2.
- README updated with a v2.2 safety-posture note and the opt-in flags.
- Final verification: full suite **130 passing, 0 failing**; app factory boots
  clean.

## Summary of the pass

| # | Iteration | Outcome |
|---|-----------|---------|
| 1 | Authorization gate | Fixed auto-approve; approve/reject added |
| 2 | Target guard | SSRF/internal-target protection wired everywhere |
| 3 | Credential-spray hardening | Simulate-by-default, consent, scope |
| 4 | Input validation | Size limit, JSON errors, validation helpers |
| 5 | Transport headers | CSP, HSTS, Permissions-Policy |
| 6 | Tests | Fixed stale tests; +17; suite green |
| 7 | Observability | Request IDs, access log, readiness probe |
| 8 | Frontend | CSP font fix; accessibility |
| 9 | Deployment | Documented safety vars; .dockerignore |
| 10 | Docs | CHANGELOG, README, final verification |

Tests: 111 passing / 2 failing (baseline) -> 130 passing / 0 failing.
Every change preserved prior capability; the one offensive component was
hardened, not sharpened; no exploit-execution was added.

---

## Iteration 11 — API-level tests for the security-critical fixes

**Context.** The original 10-iteration request was complete. This follow-on
adds end-to-end proof for the two most important changes, which previously had
only unit-level guard coverage.

**Change.**
- New `tests/test_pentest_api_gate.py` (4 tests): authorizations start
  `pending` and cannot be self-approved (analyst 403, admin 200); credential
  spraying requires per-run consent (400 without it), requires a project with
  an approved in-scope authorization (403 otherwise), and runs in simulation
  with a reported mode once authorized. Hermetic: uses the `.invalid` TLD so no
  real DNS is needed.
- Modernized three `Authorization.query.get()` call sites to
  `db.session.get()` (removes a SQLAlchemy 2.0 legacy warning; matches the
  pattern used elsewhere in the file).

**Result.** The gate and consent controls are now proven at the API layer.
Full suite: **134 passing, 0 failing.**
