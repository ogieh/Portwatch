# PortWatch Pro: Build Log and Architecture

> Living document. Updated as each phase completes. This is the audit trail of how
> the original PortWatch scanner was upgraded into a sellable, multi-tenant security
> monitoring platform suitable for a final-year project defence.

---

## 1. Starting point (discovery)

The original **PortWatch** was a single-user attack-surface scanner:

| Layer | What existed |
|-------|--------------|
| Backend | Flask app wrapping nmap. Two-phase scan model, 3 profiles (quick/standard/deep), NSE web + DB scripts, opt-in credential/lockout tester, explainable 100-point risk score, OWASP Top 10 mapping, scan diffing, printable HTML report. SQLite storage. |
| Frontend | One dark-themed page, vanilla HTML/CSS/JS. |
| Gaps | No users, no auth, no projects, no dashboard, no scheduling, no CVE intel, no notifications, no packaging. Anyone could hit the API. Flat scan list. |

**Design principle for the upgrade:** preserve the proven scan engine byte-for-byte
where possible; build the product layer *around* it, never gut it.

---

## 2. Target architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Frontend SPA (vanilla JS, hash router)                        │
│  Login · Dashboard · Projects · Scan detail · Schedules ·      │
│  Reports · Settings                                            │
└───────────────┬──────────────────────────────────────────────┘
                │ REST + JWT (Bearer)
┌───────────────▼──────────────────────────────────────────────┐
│  Flask API (application factory)                               │
│  /api/auth        register / login / me                        │
│  /api/projects    CRUD + per-project stats                     │
│  /api/scans       run / list / detail / diff / delete          │
│  /api/schedules   CRUD recurring scans                         │
│  /api/dashboard   KPIs + trend series                          │
│  /api/reports     HTML / PDF export                            │
│  /api/notifications  channels + test                           │
└───────────────┬──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│  Services                                                      │
│  scanner (original engine, preserved) · scoring · compliance · │
│  diffing · authtest · cve_intel (new) · scheduler (new) ·      │
│  notifier (new) · report (upgraded)                            │
└───────────────┬──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│  SQLite (SQLAlchemy models): users · projects · scans ·        │
│  schedules · notification_channels                             │
└──────────────────────────────────────────────────────────────┘
```

Key deliberate decisions:

- **Application factory + blueprints** so the app is testable and importable, not a
  single 3 KB module.
- **SQLAlchemy** replaces the raw-sqlite layer so we can add relationships
  (user → projects → scans) without hand-writing migrations. The original scan
  JSON shape is stored intact in a JSON column so nothing downstream breaks.
- **Simulation fallback:** nmap is not installable in every environment (marking
  a project, a laptop, CI). The scanner now has a `PORTWATCH_SIMULATE` mode that
  produces realistic synthetic scans so the whole product is demonstrable without
  root/nmap. Real nmap is used automatically when present.
- **No new heavy frontend framework.** Keeps the build inspectable and matches the
  original's zero-dependency ethos; a hash router + fetch layer is enough.

---

## 3. Phases

- [x] **Phase 0**: Discovery, scaffold, this document.
- [x] **Phase 1**: Core platform: config, SQLAlchemy models, app factory, auth (JWT).
- [x] **Phase 2**: Port the scan engine as a service + simulation fallback + CVE intel.
- [x] **Phase 3**: API blueprints: projects, scans, dashboard, schedules, notifications, reports.
- [x] **Phase 4**: Background scheduler for recurring scans.
- [x] **Phase 5**: Frontend SPA: auth, dashboard, projects, scan detail, schedules, settings.
- [x] **Phase 6**: Upgraded reporting (branded, multi-section, print/PDF).
- [x] **Phase 7**: Packaging: Docker, seed/demo data, README, architecture & defence docs.

---

## 4. Change log

| Date | Phase | Change |
|------|-------|--------|
| 2026-09-08 | 0 | Discovery complete; scaffold + build log created. |
| 2026-09-08 | 1 | Config, SQLAlchemy models (User/Project/Scan/Schedule/Channel), JWT security layer. |
| 2026-09-08 | 2 | Scan engine ported (real + simulation), CVE-intel service, scan orchestration, notifier, upgraded report. Preserved scoring/compliance/diffing/authtest unchanged. |
| 2026-09-08 | 3 | API blueprints: auth, projects, scans, dashboard, schedules, notifications. |
| 2026-09-08 | 4 | APScheduler background scheduler + application factory + SPA serving. |
| 2026-09-08 | 5 | Frontend SPA: api/components/views/app. Auth, dashboard, projects, project & scan detail, schedules, settings, modals, charts. Verified end-to-end in headless Chromium (auth→project→scan→diff→schedule→run-now→notify→dashboard, session persists on reload, zero JS errors). |
| 2026-09-08 | 6 | Report upgraded (intel section + branding); verified served at 200 with intel content. Favicon added. |
| 2026-09-08 | 7 | Packaging: seed.py (demo data), Dockerfile + docker-compose, README, ARCHITECTURE.md, test_backend.py (27/27 pass), screenshots. Replaced deprecated datetime.utcnow() app-wide with a tz-aware helper. |
| 2026-09-11 | 8 | Discovery: re-read the whole codebase, ran the 27-test baseline (all pass). Found one latent bug: the report link was a plain `<a href>` to an authenticated route, so it returned 401 in a real browser (the headless check had used the test client). |
| 2026-09-11 | 8 | P0 authorisation gate: `Scan.authorised` and `Schedule.authorised` columns, `authorised: true` required on `POST /api/scan` and `POST /api/schedules` (403 otherwise), consent checkbox in both modal forms, per-project `allowed_targets` allowlist (exact host or `*.suffix`) enforced for scans and schedules, shown on the project page and editable in the project form. Legacy schedules without recorded consent are disabled by the scheduler and get a "Confirm authorisation" action. |
| 2026-09-11 | 8 | P0 secret: `PORTWATCH_ENV=production` refuses to boot with the dev secret or a secret under 16 chars (`core/config.validate`); development logs a warning. Docker image runs in production mode; compose requires `PORTWATCH_SECRET`. |
| 2026-09-11 | 8 | Audit log: append-only `audit_log` table, `services/audit.py`, `GET /api/audit` (own events for analysts, all for admins), Settings view. Records auth, scan, project, schedule, channel and API-key events with actor and client IP; rows survive user deletion. |
| 2026-09-11 | 8 | Background scans: `services/scan_jobs.py` thread pool; `POST /api/scan` returns 202 and the SPA polls; `POST /api/scans/<id>/cancel`; per-profile ceilings (`SCAN_MAX_SECONDS`) with late results discarded; `?wait=1` for scripts; scan rows carry status/error/started/finished. Scheduler and run-now use the same queue. Two hooks added to the preserved engine: `scan_type` (-sT/-sS) and `cancel_check` between phases. Scan detail view gained queued/running (with cancel) and failed/cancelled states. |
| 2026-09-11 | 8 | Token lifecycle: 1-hour access JWT carrying `token_version`; rotating hashed refresh tokens (`/auth/refresh`, `/auth/logout`); `/auth/logout-all`; `/auth/password` change; `/auth/forgot` + `/auth/reset` (hashed single-use 30-minute token, emailed via SMTP, echoed only in development without SMTP); frontend refreshes silently on 401 and retries once. Forgot/reset screens added to the SPA. |
| 2026-09-11 | 8 | API keys: `pwp_` keys, SHA-256 at rest, shown once, revocable, accepted as Bearer or `X-API-Key`, scans tagged `trigger=api`, account routes refuse them. Settings UI. |
| 2026-09-11 | 8 | Rate limiting: dependency-free fixed-window limiter (`core/ratelimit.py`) on login, register, forgot/reset (per IP) and scan (per user); 429 with `Retry-After`. CORS: open in development, listed origins only in production. Security headers on every response. |
| 2026-09-11 | 8 | Migrations: Alembic wired into the app (`core/migrate.py`, runs on boot); `0001_baseline` = 2.0 schema, `0002_hardening` = 2.1 additions. A 2.0 database created by the original `create_all()` is stamped and upgraded automatically; verified with a database produced by the original 2.0 code. PostgreSQL: `psycopg` in requirements, compose `postgres` profile with healthcheck and a nightly `pg_dump` backup container. |
| 2026-09-11 | 8 | Packaging: gunicorn (1 worker, 8 threads) instead of the dev server, non-root container user, nmap file capabilities + compose `cap_add` for SYN mode, healthcheck, `.env.example`. `docs/DEPLOYMENT.md` written (VPS, TLS, nmap modes, backups, restore, live-engine validation). |
| 2026-09-11 | 8 | Tests: suite moved to pytest under `backend/tests` (113 tests): API flow, ownership, authorisation gate, allowlists, token lifecycle, reset, API keys, rate limiting, audit, background jobs (threaded path, cancel, timeout, engine failure, scheduler pass), real engine through a fake `PortScanner` (shape contract, phase arguments, scan type, script-failure isolation, credential opt-in, cancel), migrations (fresh, legacy, downgrade round trip), scoring boundaries and caps, every CVE regex positive and negative, diffing, notifier. `test_backend.py` kept as the runner and prints coverage (88 percent). |
| 2026-09-11 | 8 | Bug found by the new tests: the Exim CVE-2019-10149 regex (`Exim\s*4\.9`) matched patched 4.94 builds and produced a false critical finding (the simulation catalog contains "Exim 4.94"). Narrowed to 4.87 through 4.91. |
| 2026-09-11 | 8 | `fmtRelative` rendered future timestamps (a schedule's next run) as "just now"; now shows "in 24h". |
| 2026-09-11 | 8 | Report link fixed: the SPA now fetches the report with the bearer token and opens it from a blob URL. Verified in headless Chromium. |
| 2026-09-11 | 8 | CI: `.github/workflows/ci.yml` runs the suite with coverage on Python 3.11 and 3.12, seeds the demo data, syntax-checks the frontend, enforces the no-em-dash rule, builds the Docker image and checks `/api/health` from the running container. |
| 2026-09-11 | 8 | Docs: `docs/THREAT_MODEL.md` (scope, assets, threats and mitigations, data handling, limitations, responsible-use statement), README and ARCHITECTURE updated for 2.1, REMAINING_WORK rewritten, em dashes removed from code, strings, docs and the table placeholder glyph. Screenshots regenerated from the 2.1 UI (still simulated data). |

## 5. Verification summary

- **Backend:** `test_backend.py` → 27/27 assertions pass, including per-user
  ownership isolation, CVE intel, diffing, scheduling, notifications, report.
- **Frontend:** full flow driven in headless Chromium: auth → project → scan →
  diff → schedule → run-now → notify → dashboard; session persists on reload;
  zero JS/page errors (favicon route added to remove the only console noise).
- **Engine:** runs identically in simulated and (where nmap present) live mode;
  deterministic per-target simulation gives realistic diffs/trends.
- **Packaging:** `docker compose up --build` runs the whole stack with nmap
  baked in; `python seed.py` populates a demo tenant in seconds.
