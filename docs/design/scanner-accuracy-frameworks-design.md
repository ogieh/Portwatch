# Scanner Accuracy & Additional Frameworks — Design Spec

**Date:** 2026-11-05
**Status:** Approved for planning
**Branch:** `feature/scanner-accuracy-frameworks`

## 1. Purpose & Intent

Two goals, both approved by the project owner:

1. **Detection coverage** — catch open ports and services the current nmap-only
   engine misses, by promoting fast external port sweepers (RustScan, naabu,
   masscan) from *test-only validators* to *first-class production engines*, and
   widening the scanned range.
2. **Vulnerability depth** — go beyond "port X is open" to tool-confirmed
   findings by integrating **nuclei**, the standard templated vulnerability
   framework, plus a light expansion of the nmap NSE script bundle.

### Success criteria

- A scan with a sweeper installed discovers open ports across a wider range
  (up to all 65,535 on the deep profile) than today's top-ports nmap scan.
- Each discovered port records which engine(s) saw it and a confidence level.
- A scan with nuclei installed produces normalized, auditable vulnerability
  findings that feed scoring and CVE intelligence.
- **With no new tools installed, behavior is unchanged** (byte-for-byte on the
  real path, same canonical output shape).
- The whole feature is demonstrable in simulation mode with no tools installed.

### Non-goals

- No change to the canonical scan-result dict's existing keys (scoring,
  compliance, diffing, reports all depend on it — additions only).
- No change to the deterministic, line-by-line-auditable scoring model's
  existing weights. Confidence is informational, not a score multiplier.
- No new authentication, scheduling, or UI framework. The new data surfaces
  through the existing views/report.
- Not a rewrite of the preserved nmap engine; it is wrapped, not replaced.

## 2. Hard Constraints (inherited from the codebase)

- **Canonical scan dict** (`scanner.run_scan` return value) keeps every current
  key: `target, profile, credential_checks, resolved_host, ports[], summary,
  engine`. Each port keeps `port, state, service, version, risk, scripts`.
  New keys are additive and ignored by current consumers.
- **Degradation rule:** a missing external tool is never an error. It falls back
  silently, exactly as nmap → simulation does today.
- **Authorization:** every scan already passes through `scan_service.request_scan`
  (consent + `project.target_allowed`) and `core/target_guard`. The new active
  stages (nuclei, sweepers) run only inside that gate. No new bypass.
- **Cancellation & timeouts:** the pipeline polls `cancel_check` between stages
  and stays within the per-profile `SCAN_MAX_SECONDS` ceiling.
- **Test-harness independence:** `backend/tests/differential/independent_scanner.py`
  must NOT import production code. Production sweeper adapters get their own
  copy under `services/`; the harness keeps its independent copy. Agreement
  between them stays real evidence, not a tautology.

## 3. Architecture

### 3.1 Discovery → Detection pipeline

New module: **`backend/services/port_sweep.py`**

- `available_sweeper()` → returns the preferred installed tool name honoring the
  `PORT_SWEEPER` config (`auto` prefers rustscan → naabu → masscan; an explicit
  name forces that tool; `off` disables sweeping), or `None`.
- `sweep(target, port_spec, timeout, cancel_check)` → runs the selected sweeper
  over `port_spec`, returns `{port: set(engine_names)}` for open ports. Owns its
  own output parsers (rustscan greppable, naabu `host:port`, masscan stdout),
  independent of the test harness copy.
- Each parser is a pure function `str -> set[int]` for unit testing.

`scanner.py` real-engine flow becomes:

1. **Discovery stage.** If a sweeper is available, sweep the profile's
   `sweep_range`; collect the open-port set and per-port `seen_by`.
   If no sweeper is available, skip — nmap runs today's `--top-ports` phase
   unchanged (fully backward compatible).
2. **Detection stage.** nmap `-sV` runs against the discovered port set (via
   `-p <csv>`) instead of `--top-ports` when discovery ran; otherwise unchanged.
   nmap is always added to each matched port's `seen_by`.
3. **Script stage.** Unchanged (web NSE + DB scripts), plus NSE expansion (3.4).
4. **Nuclei stage.** New (3.3).
5. **Credential stage.** Unchanged.

### 3.2 Confidence field (additive)

Each port dict gains:

- `seen_by`: sorted list of engines that observed the port open,
  e.g. `["nmap", "rustscan"]`.
- `confidence`: `"confirmed"` when `len(seen_by) >= 2` (independent agreement),
  else `"single-engine"`.

Informational only: surfaced in the UI and report, **not** used in scoring.
Current consumers ignore the unknown keys.

### 3.3 Nuclei stage

New module: **`backend/services/nuclei_scan.py`** (mirrors `web_vuln.py`).

- `nuclei_available()` → `shutil.which("nuclei")` and config gate.
- `run_nuclei(target, open_web_ports, min_severity, tags, timeout, cancel_check)`:
  - Builds candidate URLs from open HTTP(S) ports (`http://` for 80/8080,
    `https://` for 443/8443, etc.).
  - Runs `nuclei -jsonl -silent -severity <floor-and-above> [-tags ...]
    -timeout <per-req> -u <urls>`.
  - Parses JSONL (one finding per line) into normalized findings:
    `{template_id, name, severity, matched_at, host, port, description,
    reference, cvss}`.
  - Returns `{"enabled": True, "findings": [...], "engine": "nuclei"}` or a
    no-op `{"enabled": False, ...}` when unavailable.
- **Merge:** findings attach to a top-level `result["nuclei"]` list, and each
  finding also annotates its port's `scripts` under a namespaced key
  `nuclei:<template_id>` so existing per-port views show it.
- **Gating:** only runs within the authorization gate; `min_severity` floor is
  configurable; bounded by `NUCLEI_TIMEOUT` inside the profile ceiling.

### 3.4 NSE expansion

Add protocol-level `vuln`/`safe` NSE scripts that nuclei does not cover
(e.g. `smb-vuln-*` on 445, `ftp-anon` on 21, `ssl-poodle`), appended to the
existing `NSE_SCRIPTS` bundle and run in the same script phase. Script names
remain parseable by scoring's existing `http-vuln-*` / SSL logic where the
naming matches; new families get explicit handling in scoring (3.5).

### 3.5 Scoring & intel wiring

- **`scoring.py`:** add nuclei penalties, severity-weighted with a cap, emitted
  as auditable line items alongside the existing deductions:
  - `critical` → 25, `high` → 18, `medium` → 8, `low` → 3, `info` → 0,
    capped at `NUCLEI_PENALTY_CAP = 45`. (Final weights confirmed during
    implementation against the ground-truth harness.)
  - Deductions reference the template id so the breakdown stays explainable.
  - New NSE families (3.4) get explicit penalty handling where they report a
    vulnerable state.
- **`cve_intel.py`:** nuclei findings become tool-confirmed (highest-confidence)
  intel entries, carrying the template's `reference`/CVE and `cvss` when present,
  slotting into the existing confidence model next to NSE-confirmed CVEs.

### 3.6 Config & profiles

New `Config` settings (all env-overridable, documented in `.env.example`):

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `PORT_SWEEPER` | `PORTWATCH_PORT_SWEEPER` | `auto` | `auto`/`rustscan`/`naabu`/`masscan`/`off` |
| `NUCLEI_ENABLED` | `PORTWATCH_NUCLEI` | `auto` | `auto` = on if installed |
| `NUCLEI_MIN_SEVERITY` | `PORTWATCH_NUCLEI_SEVERITY` | `low` | severity floor |
| `NUCLEI_TAGS` | `PORTWATCH_NUCLEI_TAGS` | *(empty)* | optional template tag filter |
| `NUCLEI_TIMEOUT` | `PORTWATCH_NUCLEI_TIMEOUT` | `300` | nuclei stage ceiling (s) |

Each `SCAN_PROFILES` entry gains a `sweep_range`:

- `quick` → top 100, `standard` → top 1000, `deep` → `1-65535`.

When no sweeper is installed, `sweep_range` is ignored and the existing
`phase1_arguments` top-ports values apply (unchanged behavior).

### 3.7 Simulation

- `_simulate_scan` populates `seen_by`/`confidence` (sometimes multi-engine) so
  the confidence UI is demonstrable with no tools installed.
- A new `_simulate_nuclei` emits a few realistic templated findings on open web
  ports (same deterministic, seeded style as `_simulate_scripts`), so the
  nuclei layer shows end-to-end in simulation mode.

## 4. Data flow

```
request_scan (auth gate, allowlist)  ──>  execute_scan
                                             │
                        scanner.run_scan ────┤
                          ├─ discovery: port_sweep.sweep()  → seen_by{}
                          ├─ detection: nmap -sV on open set → ports[], +nmap seen_by
                          ├─ scripts:  NSE (web/db + expansion)
                          ├─ nuclei:   nuclei_scan.run_nuclei() → result["nuclei"]
                          └─ creds:    authtest (unchanged)
                                             │
                        _enrich ─ scoring (+nuclei penalties)
                                 ─ compliance
                                 ─ cve_intel (nuclei = confirmed)
```

## 5. Error handling

- Every external tool wrapped in try/except; failure → logged, stage yields an
  empty result, scan continues. Never raises out of a stage.
- Malformed tool output → parser returns an empty set / empty findings.
- Cancellation checked between stages, raising `ScanCancelled` (existing path).
- Stage timeouts are independent subprocess timeouts within the profile ceiling.

## 6. Testing

- **Unit (mocked, no network):** each sweeper parser (`str -> set[int]`); nuclei
  JSONL parser; merge + `seen_by`/`confidence` assignment; nuclei scoring
  penalties and cap; graceful absence (tool not on PATH → no-op); config gating
  (`off`, explicit tool, severity floor).
- **Differential harness:** add a check that production `port_sweep` discovery
  agrees with the harness's independent socket oracle; keep the harness's own
  adapter copy separate from the production copy.
- **Ground truth:** expectation that nuclei flags the lab's deliberately
  vulnerable Apache 2.4.49 (CVE-2021-41773) in `docker/lab/`.
- **Regression:** with all new tools absent, a scan's output matches today's
  shape and values (backward-compat test).

## 7. Documentation (required deliverable)

The project owner asked that the README explain everything added and its
purpose. Implementation must update:

- **`README.md`:** the feature table and a new subsection describing the
  discovery→detection pipeline, the confidence field, nuclei integration, the
  NSE expansion, and *why each was added* (accuracy / coverage / confirmed
  findings). Document the degradation behavior and the new config/env vars.
- **`.env.example`:** the new env vars with comments.
- **`docs/ARCHITECTURE.md`:** the pipeline stages and new modules.
- **`CHANGELOG.md`:** a dated entry for this feature.

## 8. New / changed files (anticipated)

- New: `backend/services/port_sweep.py`, `backend/services/nuclei_scan.py`
- Changed: `backend/services/scanner.py`, `scoring.py`, `cve_intel.py`,
  `core/config.py`, `.env.example`, `README.md`, `docs/ARCHITECTURE.md`,
  `CHANGELOG.md`
- New tests under `backend/tests/` and additions to
  `backend/tests/differential/` and `backend/tests/ground_truth/`.
