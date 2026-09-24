# PortWatch Pro: Architecture and Design

This document explains how the system is built and, more importantly, **why**
each decision was made. It is written to be read alongside the code during a
project defence.

---

## 1. From script to product

The original PortWatch was a competent single-file scanner: a Flask route that
called nmap and rendered results on one page. It had no notion of *who* was
scanning, *what* they were monitoring over time, or *how* to operate it as a
service. Turning it into a sellable product meant adding the layers that
separate a tool from an application:

1. **Identity**: accounts and per-user data isolation.
2. **Organisation**: projects grouping many scans of many targets.
3. **Continuity**: history, trends, diffs, and scheduled re-scanning.
4. **Intelligence**: turning raw findings into CVEs and remediation.
5. **Operability**: dashboard, notifications, reporting, packaging.

The guiding constraint throughout: **do not rewrite the proven scan engine.**
The scoring, compliance, diffing and credential-testing modules carry real
engineering judgement (visible in their comments). They were copied in verbatim
and wrapped, not rebuilt.

---

## 2. Layered structure

```
┌──────────────────────── Presentation ────────────────────────┐
│ frontend/  Vanilla-JS SPA. api.js (transport) · components.js │
│            (render helpers) · views.js (pages) · app.js       │
│            (router + shell). Hash routing → deep links survive │
│            refresh. JWT kept in localStorage.                 │
└───────────────────────────────┬───────────────────────────────┘
                                 │ JSON / REST / Bearer JWT
┌───────────────────────────────▼───────────────────────────────┐
│ API   backend/api/  One blueprint per resource. Thin: validate │
│       input, enforce ownership, call a service, return JSON.    │
├────────────────────────────────────────────────────────────────┤
│ Services  backend/services/  All logic lives here.             │
│   scanner ─ engine (real nmap + simulation), preserved profiles │
│   scoring ─ PRESERVED risk model                               │
│   compliance ─ PRESERVED OWASP mapping                         │
│   diffing ─ PRESERVED scan comparison                          │
│   authtest ─ PRESERVED credential/lockout tester              │
│   cve_intel ─ NEW vulnerability knowledge base                 │
│   scan_service ─ NEW orchestration (single scan path)          │
│   scheduler_service ─ NEW background recurring scans           │
│   notifier ─ NEW email/webhook alerts                          │
│   report ─ UPGRADED branded HTML/PDF report                    │
├────────────────────────────────────────────────────────────────┤
│ Data  backend/models/  SQLAlchemy models + one db instance.    │
│       core/  config, security (JWT/refresh/API keys),          │
│             ratelimit, migrate (Alembic on boot).               │
└────────────────────────────────────────────────────────────────┘
```

Why this shape:

- **Thin API, fat services.** Routes never contain business logic, so the exact
  same `scan_service.perform_scan()` runs whether a scan is triggered by a user
  clicking *Scan*, by the scheduler, or by a *Run now* button. There is one
  place a scan can go wrong, not three.
- **Application factory** (`create_app`) makes the app importable and testable -
  `test_backend.py` builds an app with a test config and drives it with Flask's
  test client, no live server needed.
- **Blueprints** keep each resource's routes together and independently
  reviewable.

---

## 3. The data model

```
User ─1───*─ Project ─1───*─ Scan
  │            (allowed_targets)   (full_data: JSON blob of the entire
  ├─1───*─ Schedule ─*──1 Project    original scan dict: ports, scripts,
  ├─1───*─ NotificationChannel       risk, compliance, credential_checks,
  ├─1───*─ RefreshToken              intel) plus lifecycle columns:
  ├─1───*─ PasswordResetToken        status, error, started_at,
  ├─1───*─ ApiKey                    finished_at, authorised,
  └─1───*─ AuditLog (append-only)    credential_checks, requested_by
```

The key decision is **Scan.full_data**. The original scan produces a rich nested
dict. Rather than shredding it into relational tables (and coupling the schema
to the engine's output shape), the whole dict is stored as JSON in one column,
with the few fields needed for listing and filtering (`target`, `profile`,
`risk_score`, `risk_grade`, `timestamp`, `trigger`) promoted to real columns and
indexed. This means:

- Every consumer written against the original shape keeps working unchanged.
- History is immutable: a scan is scored at save time, so changing the scoring
  formula later never silently re-grades old scans (a property the original
  author deliberately built in, preserved here).
- Adding a new derived section (like `intel`) required **zero migration**.

Ownership is enforced at the query layer: every scan/schedule/channel lookup
joins back to the authenticated user, so one user can never read another's data
even by guessing IDs.

Schema changes are Alembic migrations (`backend/migrations`). `0001_baseline`
is the 2.0 schema; `0002_hardening` adds the 2.1 columns and tables. On boot,
`core/migrate.upgrade_to_head()` recognises a database created by 2.0's
`create_all()` (tables present, no `alembic_version`), stamps it at the
baseline and upgrades it, so an existing install migrates with no manual step.
Existing scans are back-filled as `completed` and `authorised = false`: consent
that was never recorded is not invented.

---

## 4. The scan engine and simulation

The real engine is the original two-phase model:

1. **Phase 1**: fast, reliable port discovery (`-sV -Pn --top-ports N`).
2. **Phase 2**: best-effort NSE scripts on open web/DB ports; failures here
   never wipe out phase-1 results.
3. **Phase 3 (opt-in)**: credential/lockout probing.

**Simulation** was added because a security scanner is hard to demonstrate:
examiners' laptops rarely have nmap + root, and scanning real hosts without
authorisation is illegal. The simulation engine:

- produces results in the **identical dict shape**, so nothing downstream can
  tell the difference;
- is **seeded per target** (`sha256(target|profile)`), so a target looks
  consistent across scans, diffs and trends behave realistically;
- widens what it reveals with deeper profiles, mirroring real nmap behaviour;
- generates plausible NSE script output (weak ciphers, missing headers,
  CVE hits, empty DB passwords) so scoring, compliance and intel all light up.

The engine is chosen automatically: real nmap if present, simulation otherwise,
overridable with `PORTWATCH_SIMULATE`. The active mode is surfaced in the UI so
it is never misleading.

Two small hooks were added to the preserved real engine in 2.1. `scan_type`
prepends `-sT` (connect, unprivileged) or `-sS` (SYN, needs `CAP_NET_RAW`) to
every nmap invocation, so the container can run scans as a non-root user.
`cancel_check` is polled between phases and raises `ScanCancelled`; the phases
and arguments are otherwise unchanged. `tests/test_real_engine.py` drives the
real engine through a fake `PortScanner` and asserts its output has exactly the
simulation's shape, which is the contract everything above the engine relies on.

### 4a. Background execution

A deep scan can take minutes, so 2.1 moved every scan off the request thread.
`POST /api/scan` validates, creates a Scan row in status `queued`, hands the
id to `scan_jobs` (a small `ThreadPoolExecutor`) and returns 202. The row
moves through `running` to `completed`, `failed` or `cancelled`; the SPA polls
`GET /api/scans/<id>` until it settles. `?wait=1` blocks up to 25 seconds for
scripts. Each job runs the engine in an inner thread and joins it with the
profile's ceiling (`SCAN_MAX_SECONDS`); on overrun the scan is marked failed,
the cancel flag is set, and any late result is discarded because a finalised
row is never overwritten. Manual, API-key and scheduled scans all go through
`scan_service.request_scan()` + `scan_jobs.submit()`, so there is still one
path.

---

## 5. Vulnerability intelligence (new)

`cve_intel.py` is an **offline, deterministic** knowledge layer, no external
API, so it works air-gapped and in a demo. It has three sources, in descending
confidence:

1. **Script-confirmed**: an NSE `http-vuln-*` script reported VULNERABLE →
   mapped to its canonical CVE (e.g. CVE-2021-41773).
2. **Version-likely**: a service banner matches a known-vulnerable range via
   regex (e.g. `vsftpd 2.3.4` → CVE-2011-2523 backdoor).
3. **Exposure guidance**: an inherently risky service is reachable (Redis,
   RDP, Telnet, exposed DBs).

Every finding carries a `confidence` field and a concrete remediation string, so
the report is honest about *proven* vs *inferred* and always actionable. This is
the single biggest credibility upgrade over the original: it turns "port 6379 is
open" into "Redis exposed, unauthenticated Redis is trivially abused; require a
password and bind to localhost."

---

## 6. Scheduling (new)

`scheduler_service.py` runs one APScheduler background job that wakes on an
interval, finds `Schedule` rows whose `next_run` is due, and queues each through
`scan_service.request_scan(trigger="scheduled")` + `scan_jobs.submit()`, the
same path as a manual scan. Design points:

- **App context is pushed explicitly**: the job runs off the request thread, so
  there is no ambient Flask/DB context; the service creates one.
- **One failing schedule never stops the others**: each run is wrapped.
- **Idempotent orphan handling**: a schedule whose project was deleted disables
  itself instead of erroring forever.
- Bounded (`max_instances=1`, `coalesce=True`) so a slow scan can't stack jobs.
- **Consent is never assumed**: a schedule with no recorded authorisation
  (for example one created before 2.1) is disabled, not run, and the user is
  asked to confirm authorisation in the UI.

This is what makes PortWatch "monitoring" rather than "scanning": posture is
watched continuously, and combined with notifications, a new exposure pages the
team without anyone clicking anything.

---

## 7. Notifications (new)

`notifier.py` fires after every scan. A channel has a grade threshold
(`min_grade`); it alerts only when a scan's grade is at or below it, so teams
aren't paged for healthy scans. Two kinds:

- **Webhook**: POSTs JSON with a Slack-compatible `text` field.
- **Email**: SMTP if configured; otherwise a logged no-op so the feature never
  crashes a scan when SMTP is absent.

Every dispatch path is wrapped: **a notification failure can never abort a
scan.** This ordering, persist the scan first, then notify, means results are
never lost to a flaky webhook.

---

## 8. Security posture of the app itself

- Passwords hashed with Werkzeug (scrypt).
- Short-lived access JWTs (1 hour, HS256) carrying the user's `token_version`;
  opaque refresh tokens stored hashed and rotated on use; "sign out everywhere"
  and password changes bump `token_version` so every access token dies at once.
- Revocable API keys (`pwp_...`, SHA-256 at rest, shown once) for scripted
  scanning; they cannot manage the account.
- Password reset by single-use, 30-minute hashed token; the forgot endpoint
  never reveals whether an address exists.
- Authorisation gate: every scan and schedule needs `authorised: true`, which
  is stored and audited; projects may carry a target allowlist.
- Rate limiting (in-process fixed window) on login, register, reset and scan.
- Append-only audit log with actor and IP for auth, scan, project, schedule
  and channel events.
- Per-request ownership checks on every resource.
- Security headers on every response; production CORS off unless listed.
- Input validation on every write route (email format, profile whitelist,
  interval bounds, URL scheme for webhooks).
- HTML report output is fully escaped (`html.escape`) to prevent stored-XSS via
  service banners or script output.
- The credential tester is opt-in per scan and honest about its limits
  ("none observed within N probes", never "unlimited").

Known limitations (stated plainly for a defence): the consent checkbox is an
attestation, not proof; the rate limiter and scan queue are per process (the
documented deployment is one gunicorn worker); a cancel takes effect at the
next phase boundary, not mid-nmap. `docs/THREAT_MODEL.md` has the full list.
Production refuses to start with the default `PORTWATCH_SECRET`; SQLite suits a
single-node deployment and the compose `postgres` profile is the scale path.

---

## 9. Frontend design

The original established a deliberate operator aesthetic, deep-navy surface,
JetBrains Mono for data, Inter for UI, cyan accent, semantic risk colours. Rather
than introduce a competing visual language, the SPA **extends that system**
consistently across every new view. No heavy framework: a hash router plus a
small fetch layer keeps the frontend inspectable and matches the original's
zero-dependency ethos, while still delivering a genuine multi-page app with a
dashboard, charts (hand-rolled SVG donut + bars, no chart library), modals,
toasts, and empty/loading/error states everywhere.

---

## 10. What a reviewer can verify quickly

- `python seed.py` then log in → a populated dashboard in under a minute.
- Run a scan on any string → grade, CVE intel, OWASP mapping, report.
- Scan the same target twice → open a diff.
- Create a schedule, hit *Run now* → a scan tagged `scheduled` appears.
- `python test_backend.py` → the whole API exercised headless.
- Toggle `PORTWATCH_SIMULATE` / install nmap → engine badge changes; identical UI.
