# Changelog

## Hardening & quality pass (v2.2)

A governance-first improvement pass over PortWatch Pro v2.1. Ten auditable
iterations, each a separate commit. Full detail in `docs/ITERATION_LOG.md`.

### Security fixes

- **Authorization gate restored.** `create_authorization` auto-approved every
  authorization on creation, silently defeating the platform's central consent
  control. Non-superadmin authorizations now start `pending` and require
  explicit approval by a separate admin. New `approve`/`reject` endpoints and
  audit events.
- **Target guard (SSRF / internal-target protection).** New
  `core/target_guard.py` blocks loopback, link-local, cloud-metadata
  (169.254.169.254), and private ranges by default; resolves hostnames and
  checks every resolved address; caps CIDR sweeps. Enforced at the scan engine
  and every active-probe route.
- **Credential spraying hardened.** Simulation is now the default; live testing
  requires the server-side `LIVE_CREDENTIAL_TESTING` opt-in. Added service-layer
  target guarding, a per-run consent requirement (`confirm_authorized`),
  mandatory scoped authorization, a username cap, and live/simulated mode in the
  audit log.

### Robustness

- Request body size limit (`MAX_CONTENT_LENGTH`, default 1 MiB) and a 413 handler.
- Consistent JSON error envelopes for 400/404/405/413/500 on API paths; 500s are
  logged without leaking stack traces. New `core/validation.py` helpers.
- Content-Security-Policy (strict `script-src 'self'`), HSTS in production over
  HTTPS, and Permissions-Policy. One inline `onclick` removed to keep the CSP
  strict. Google Fonts origins permitted in the policy.

### Observability

- Per-request `X-Request-ID` (honoured or generated) and a structured
  access-log line per request (no bodies or query strings logged).
- New `/api/ready` readiness probe that checks database connectivity (503 when
  unavailable).

### Frontend

- Accessibility: skip-to-content link, `<noscript>` fallback, `role="main"`,
  a polite `aria-live` toast region, visible `:focus-visible` ring, and a
  `prefers-reduced-motion` rule.

### Tests & tooling

- Fixed two migration tests that hardcoded the head revision; they now derive
  it dynamically. Added 17 tests for the new guards.
- Suite: **130 passing, 0 failing** (was 111 passing / 2 failing).
- Restored `requirements-dev.txt` (the uploaded copy contained unrelated shell
  commands, not dependencies).

### Deployment

- `.env.example` documents all new safety controls with safe defaults.
- New `.dockerignore` keeps the dev database, virtualenvs, tests, and secrets
  out of the image.
