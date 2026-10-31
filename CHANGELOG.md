# Changelog

## Validation and wiring pass

This one was about making the scanner's claims checkable by something other than
the scanner, and finishing the features that were half-wired.

### Checking the scanner against the outside world

- Added a reference lab (`docker/lab/`): six services in known states, each on
  its own loopback address. One of them is Apache 2.4.49 left open to
  CVE-2021-41773 on purpose, so the live NSE script has a real positive to catch.
- Added a differential harness (`backend/tests/differential/`) that runs the real
  nmap engine against the lab and compares it to an independent socket prober, and
  to a second scanner (RustScan, naabu, masscan) when one is installed. It fails
  if the lab stops matching its manifest. See `docs/DIFFERENTIAL.md`.
- Added an NVD cross-check (`backend/tests/cve_validation.py`) for the CVE
  knowledge base. It found three version-range off-by-ones (Apache 2.4.49,
  OpenSSH 7.4, ProFTPD 1.3.5a were flagged although those are the fixed releases)
  and two severity labels that didn't match their CVSS score. All fixed.

### Scoring

- Replaced the three-bucket port-count model with a per-service criticality
  table. On the reference corpus this removed all seven rank inversions and took
  the correlation with analyst severity from -0.91 to -1.0. The breakdown stays
  line-by-line. (A perfect rank on twelve hosts is an in-sample fit; the
  differential run is the real check.)

### Finishing the pentest layer

- The authorization, findings, asset, and recon endpoints had tables and a
  blueprint but no ORM models and no registration, so they all 404'd. Added the
  four models, the missing auth decorators (`require_role`, `require_superadmin`,
  `require_pentest_auth`, and the superadmin helpers), and registered the
  blueprints.
- Built the authorizations screen (consent gate with an admin approval flow) and
  the findings tracker (filter, status/assignee updates, generate from a scan).

### Cleanup and accessibility

- Deleted the stale top-level copies of the core modules that shadowed the
  canonical ones under `services/`. One source of truth now.
- Frontend accessibility: labelled the icon-only nav, trapped and restored focus
  in modals, gave the charts text alternatives, tied the auth form labels to
  their inputs, and added a skip link.

### Tests

- Fixed the two migration tests that expected a stale head revision, and the
  pentest API-gate tests that were failing because the feature wasn't wired.
- Suite: **146 passing**, with two integration gates (`PORTWATCH_LAB`,
  `PORTWATCH_NVD`) that stay skipped until you opt in. CI runs all three as
  separate jobs.

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
