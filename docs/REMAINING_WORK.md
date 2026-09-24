# PortWatch Pro - Remaining Work

> Status as of 2026-09-11 (version 2.1). This is the honest gap list after the
> hardening release: what is done, what still needs a machine this build
> environment did not have, and what is left for the submission and for the
> commercial path. File paths are relative to the project root.

---

## 1. Where the project stands

The 2.0 build (seven phases) and the 2.1 hardening phase are complete.

Verified in this environment (simulation mode; nmap and Docker were not
installable here because the package mirrors are blocked):

- `python backend/test_backend.py`: **113 tests pass, 88 percent coverage**.
- Headless Chromium click-through of every view and flow, including the
  consent gate, allowlist refusal, queued scan to detail, cancel path (by
  test), report tab, schedules, API keys, password change, audit log, forgot
  and reset. Zero page errors.
- A database created by the original 2.0 code migrates automatically and
  works under 2.1.
- Demo seed works (`backend/seed.py`, `demo@portwatch.io` / `demopass123`).

Closed since the 2026-09-08 list: authorisation gate and allowlists, real
`SECRET_KEY` enforcement, audit log, rate limiting, CORS lock-down, password
reset and change, token lifecycle (short access + rotating refresh + sign out
everywhere), API keys, background scan jobs with polling, cancellation and
per-profile ceilings, nmap scan type and container capabilities, PostgreSQL
support, Alembic migrations, nightly backups, deployment guide, expanded tests
with a coverage number, CI, threat model and ethics page, em-dash cleanup.
One latent bug (report link unauthenticated in a real browser) and one
knowledge-base bug (Exim regex matching patched versions) were found and fixed
along the way.

---

## 2. Priority key

- **P0**: must do before real use or before submission.
- **P1**: needed to call it a sellable/production product.
- **P2**: polish; strengthens the grade or the pitch.

Effort: S = under a day, M = 1 to 3 days, L = a week or more.

---

## 3. P0 - Needs a machine with nmap and Docker

- [ ] **Validate against real nmap.** (S) Everything but the nmap subprocess is
      now tested, and `tests/test_real_engine.py` pins the real engine to the
      simulation's output shape through a fake `PortScanner`. What remains is
      one live run on a machine with nmap, against a target you own or are
      authorised to test (`scanme.nmap.org` is published for this). The exact
      command is in `docs/DEPLOYMENT.md` section 5. Check that `engine` is
      `nmap`, ports 22 and 80 show open, and a scan through the UI grades and
      reports normally. Try both `PORTWATCH_NMAP_SCAN_TYPE=connect` and `syn`.
- [ ] **Build and boot the Docker image once.** (S) `docker compose up --build`
      with a `.env`. The Dockerfile and compose file were rewritten (gunicorn,
      non-root user, capabilities, healthcheck, postgres profile) but could not
      be built here. CI builds it on the first push; do it locally as well.
- [ ] **Confirm the demo path start-to-finish on the target machine.** (S)
      `python backend/seed.py`, run the app, log in as the demo user, click
      through every view, run a scan with the consent box ticked, cancel one,
      open a report, create an API key. This is the live-demo fallback.

---

## 4. P1 - Production, beyond what ships

- [ ] **Multi-process scaling.** (M) The rate limiter and the scan queue are
      in-process by design (one gunicorn worker, eight threads). If one process
      is ever a bottleneck: Flask-Limiter on Redis and an RQ or Celery queue.
      The decorator and `scan_jobs.submit/cancel` signatures were kept
      compatible with that move.
- [ ] **Mid-phase cancellation.** (S) Cancel takes effect between nmap phases;
      a phase already running finishes to nmap's own `--host-timeout`. Killing
      the nmap child process needs the engine to own the subprocess instead of
      python-nmap; only do this if users complain about cancel latency.
- [ ] **Audit-log retention.** (S) Decide a retention period and add a
      scheduled prune (a one-line SQL job). Left out deliberately so nothing
      deletes audit rows by default.
- [ ] **Password policy and 2FA.** (M) Minimum length is 8; there is no
      complexity rule, breach-list check or TOTP. Add TOTP before selling to
      security teams.
- [ ] **Email deliverability.** (S) Reset and alert mail go through plain
      SMTP with STARTTLS. Set up SPF/DKIM on the sending domain.

### Commercial layer (only if this becomes a business)
- [ ] Team accounts and sharing (invite a colleague to a project). (L)
- [ ] Plans/billing (Stripe) and per-plan scan limits. (L)
- [ ] Organisation-level audit export (CSV) and SIEM webhook. (M)

---

## 5. P2 - For the final-year submission

- [ ] **Written report / dissertation chapters.** (L) Introduction and problem
      statement, literature review (nmap, OpenVAS, Nessus, Shodan; where
      PortWatch Pro sits), methodology, system design (`docs/ARCHITECTURE.md`),
      implementation (`docs/BUILD_LOG.md` is the raw material), security and
      ethics (`docs/THREAT_MODEL.md`), **evaluation**, conclusion and future
      work (this file).
- [ ] **Evaluation with real results.** (M) Options: risk score against a
      known-vulnerable VM (Metasploitable), PortWatch output versus raw nmap,
      timing of the three profiles with the new ceilings, and a small usability
      test with 3 to 5 users. The audit log and scan `duration_seconds` give
      you timing data for free.
- [ ] **Demo video (3 to 5 minutes) and slide deck.** (M) Script the happy path;
      keep the seeded demo user as the fallback.
- [ ] **Regenerate screenshots from a real scan** once nmap is validated. The
      current `docs/screenshots/*.png` are from the 2.1 UI on simulated data.

---

## 6. Known issues and decisions

- **Table placeholder glyph.** The em-dash empty-value glyph in tables was
      replaced with a plain hyphen so the house style holds everywhere; CI now
      fails on any em dash in source or docs.
- **Legacy scans show `authorised = false`.** Scans and schedules created
      before 2.1 have no recorded consent and are back-filled as unauthorised.
      Old scans are still viewable; old schedules are disabled until someone
      confirms authorisation in the Schedules view. This is intentional.
- **Development password reset without SMTP** returns the reset token in the
      API response so the flow is testable. This happens only when
      `PORTWATCH_ENV` is not `production`.
- **Google Fonts** are loaded from the CDN by `index.html`; in an air-gapped
      deployment the UI falls back to system fonts. Vendor the two font files
      if that matters.

---

## 7. Suggested order of work

1. **Real-nmap validation + Docker build + demo path** (P0). Half a day on a
   machine with nmap and Docker. After this the tool is honestly demonstrable
   in live mode.
2. **Evaluation + written report + demo video** (P2). This is what the project
   is graded on and the biggest time sink.
3. **Production extras** (P1). Only if you deploy for paying users.

---

## 8. Quick reference

```
# from the project root
cd backend
pip install -r requirements-dev.txt

python seed.py                       # demo data (demo@portwatch.io / demopass123)
python app.py                        # http://localhost:5000 (simulation if nmap absent)
PORTWATCH_SIMULATE=1 python app.py   # force simulation

python test_backend.py               # 113 tests + coverage
python -m pytest tests -q            # same, without coverage

alembic upgrade head                 # manual migration (the app also does this on boot)
```

Docker: copy `.env.example` to `.env`, set `PORTWATCH_SECRET`, then
`docker compose up --build` (SQLite) or
`docker compose --profile postgres up --build` (PostgreSQL + nightly backups).
See `docs/DEPLOYMENT.md`.
