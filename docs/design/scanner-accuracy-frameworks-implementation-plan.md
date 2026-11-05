# Scanner Accuracy & Additional Frameworks Implementation Plan


**Goal:** Widen port-detection coverage with external sweeper engines feeding nmap `-sV`, add a per-port confidence signal, and add nuclei-confirmed vulnerability findings — all additive and backward-compatible.

**Architecture:** A discovery stage (`port_sweep.py`) runs the best installed sweeper (rustscan/naabu/masscan) over a profile range and records which engines saw each port; nmap `-sV` then runs against only the discovered ports. A new `nuclei_scan.py` stage produces confirmed findings that feed scoring and CVE intel. When no new tools are installed, the engine runs exactly as today.

**Tech Stack:** Python 3, Flask, python-nmap, subprocess wrappers for rustscan/naabu/masscan/nuclei, pytest.

**Spec:** `docs/design/scanner-accuracy-frameworks-design.md`

## Global Constraints

- Canonical scan dict keeps every existing key; new data is additive only (ports keep `port, state, service, version, risk, scripts`; result keeps `target, profile, credential_checks, resolved_host, ports, summary, engine`).
- A missing external tool is never an error — silent fallback, like nmap → simulation.
- New active stages run only inside the existing auth gate (`scan_service.request_scan`) + `core/target_guard`; no new bypass.
- Pipeline polls `cancel_check` between stages and stays within per-profile `SCAN_MAX_SECONDS`.
- `backend/tests/differential/independent_scanner.py` must NOT import production code; production sweeper adapters are a separate copy under `services/`.
- Tests import backend modules by short name (e.g. `import scanner`) via `conftest`; `conftest` sets `PORTWATCH_SIMULATE=1`. Run tests from `backend/`.
- Scoring stays deterministic and line-by-line auditable; `confidence` is informational and never alters the score.

## Review Focus

- **Sweeper output with no open ports / empty stdout** → parser returns empty set, scan continues and reports zero discovered (Task 2).
- **Malformed or partial nuclei JSONL line** → that line is skipped, valid lines still parsed, no exception (Task 3).
- **A sweeper finds a port nmap `-sV` cannot fingerprint** → port still appears with `service="unknown"` and `seen_by=["<sweeper>"]`, `confidence="single-engine"` (Task 4).
- **All new tools absent** → scan output shape and values match today's nmap/simulation behavior (backward-compat test, Task 4).
- **nuclei penalties never drive the score below 0 and respect the cap** (Task 5).

---

### Task 1: Config settings & profile sweep ranges

**Files:**
- Modify: `backend/core/config.py`
- Modify: `backend/services/scanner.py` (add `sweep_range` to each `SCAN_PROFILES` entry)
- Test: `backend/tests/test_scanner_config.py` (create)

**Interfaces:**
- Produces: `Config.PORT_SWEEPER` (str: `auto|rustscan|naabu|masscan|off`), `Config.NUCLEI_ENABLED` (str: `auto|on|off`), `Config.NUCLEI_MIN_SEVERITY` (str), `Config.NUCLEI_TAGS` (str), `Config.NUCLEI_TIMEOUT` (int). Each `scanner.SCAN_PROFILES[p]` gains key `sweep_range` (str): quick=`"--top-ports 100"`, standard=`"--top-ports 1000"`, deep=`"-p-"`.

- [ ] **Step 1: Write the failing test**
```python
# test_scanner_config.py
import scanner
from core.config import Config

def test_profiles_have_sweep_range():
    for p in ("quick", "standard", "deep"):
        assert "sweep_range" in scanner.SCAN_PROFILES[p]
    assert scanner.SCAN_PROFILES["deep"]["sweep_range"] == "-p-"

def test_config_defaults():
    assert Config.PORT_SWEEPER == "auto"
    assert Config.NUCLEI_ENABLED == "auto"
    assert Config.NUCLEI_MIN_SEVERITY == "low"
    assert isinstance(Config.NUCLEI_TIMEOUT, int)
```
- [ ] **Step 2: Run to verify it fails** — `cd backend && python -m pytest tests/test_scanner_config.py -v` → FAIL (KeyError / AttributeError)
- [ ] **Step 3: Implement** the new `Config` attributes (env-overridable via `PORTWATCH_PORT_SWEEPER`, `PORTWATCH_NUCLEI`, `PORTWATCH_NUCLEI_SEVERITY`, `PORTWATCH_NUCLEI_TAGS`, `PORTWATCH_NUCLEI_TIMEOUT`, using the existing `_int`/env helpers) and add `sweep_range` to each profile.
- [ ] **Step 4: Run to verify it passes** — same command → PASS
- [ ] **Step 5: Commit** — `git add backend/core/config.py backend/services/scanner.py backend/tests/test_scanner_config.py && git commit`

---

### Task 2: Port-sweep discovery module

**Files:**
- Create: `backend/services/port_sweep.py`
- Test: `backend/tests/test_port_sweep.py` (create)

**Interfaces:**
- Consumes: `Config.PORT_SWEEPER`.
- Produces:
  - `available_sweeper(preference="auto") -> str | None`
  - `sweep(target, port_spec, timeout, cancel_check=None) -> dict[int, set[str]]` (open port → set of engine names; `{}` when none available/found)
  - parsers `parse_rustscan(text) -> set[int]`, `parse_naabu(text) -> set[int]`, `parse_masscan(text) -> set[int]`

- [ ] **Step 1: Write the failing test** — parser cases + absence:
```python
import port_sweep

def test_parse_rustscan():
    assert port_sweep.parse_rustscan("127.0.0.1 -> [22,6379]") == {22, 6379}

def test_parse_naabu():
    assert port_sweep.parse_naabu("host:22\nhost:443\n") == {22, 443}

def test_parse_masscan():
    assert port_sweep.parse_masscan(
        "Discovered open port 6379/tcp on 1.2.3.4") == {6379}

def test_parsers_tolerate_empty():
    assert port_sweep.parse_rustscan("") == set()

def test_available_sweeper_off(monkeypatch):
    assert port_sweep.available_sweeper("off") is None
```
- [ ] **Step 2: Run to verify it fails** — `pytest tests/test_port_sweep.py -v` → FAIL (module missing)
- [ ] **Step 3: Implement** `port_sweep.py`. Parsers are pure (regex, same formats as the differential harness but an independent copy). `available_sweeper` honors preference then checks `shutil.which` in order rustscan→naabu→masscan. `sweep` runs the tool via `subprocess.run(..., timeout=timeout)`, wraps all `subprocess.SubprocessError/OSError` to return `{}`, and tags each found port with the tool name.
- [ ] **Step 4: Run to verify it passes** → PASS
- [ ] **Step 5: Commit**

---

### Task 3: Nuclei scan module

**Files:**
- Create: `backend/services/nuclei_scan.py`
- Test: `backend/tests/test_nuclei_scan.py` (create)

**Interfaces:**
- Consumes: `Config.NUCLEI_*`.
- Produces:
  - `nuclei_available() -> bool`
  - `parse_jsonl(text) -> list[dict]` (each: `template_id, name, severity, matched_at, host, port, description, reference, cvss`)
  - `run_nuclei(target, open_web_ports, min_severity="low", tags="", timeout=300, cancel_check=None, simulate=False) -> dict` → `{"enabled": bool, "findings": list, "engine": "nuclei"|"simulated"}`
  - `simulate_nuclei(target, open_web_ports) -> list[dict]` (seeded, deterministic)

- [ ] **Step 1: Write the failing test**
```python
import nuclei_scan

def test_parse_jsonl_extracts_fields():
    line = ('{"template-id":"apache-cve-2021-41773","info":{"name":"Path Traversal",'
            '"severity":"critical","reference":["CVE-2021-41773"]},'
            '"matched-at":"http://h/cgi-bin/"}')
    out = nuclei_scan.parse_jsonl(line)
    assert out[0]["template_id"] == "apache-cve-2021-41773"
    assert out[0]["severity"] == "critical"

def test_parse_jsonl_skips_malformed_lines():
    out = nuclei_scan.parse_jsonl("not json\n" + '{"template-id":"x","info":{"severity":"low"}}')
    assert len(out) == 1

def test_run_nuclei_noop_when_unavailable(monkeypatch):
    monkeypatch.setattr(nuclei_scan, "nuclei_available", lambda: False)
    r = nuclei_scan.run_nuclei("h", [80], simulate=False)
    assert r["enabled"] is False and r["findings"] == []

def test_simulate_nuclei_is_deterministic():
    assert nuclei_scan.simulate_nuclei("t", [80]) == nuclei_scan.simulate_nuclei("t", [80])
```
- [ ] **Step 2: Run to verify it fails** → FAIL (module missing)
- [ ] **Step 3: Implement** mirroring `web_vuln.py`: `run_nuclei` builds `http(s)://target:port` URLs, runs `nuclei -jsonl -silent -severity <floor>,above [-tags ...] -timeout <n> -u ...` via subprocess with timeout, calls `parse_jsonl`, wraps all errors to an empty-findings no-op; `simulate_nuclei` emits a few seeded findings (e.g. a critical on 80/443) in the same normalized shape.
- [ ] **Step 4: Run to verify it passes** → PASS
- [ ] **Step 5: Commit**

---

### Task 4: Wire the pipeline into the scanner

**Files:**
- Modify: `backend/services/scanner.py` (`_real_scan`, `_simulate_scan`, add `seen_by`/`confidence`, nuclei stage, `result["nuclei"]`)
- Test: `backend/tests/test_scanner_pipeline.py` (create)

**Interfaces:**
- Consumes: `port_sweep.sweep`, `port_sweep.available_sweeper` (Task 2); `nuclei_scan.run_nuclei`, `nuclei_scan.simulate_nuclei` (Task 3); `Config` (Task 1).
- Produces: each port dict gains `seen_by: list[str]` and `confidence: "confirmed"|"single-engine"`; result gains `nuclei: list[dict]`. `run_scan(...)` signature unchanged.

- [ ] **Step 1: Write the failing tests** (run in simulation via conftest):
```python
import scanner

def test_ports_carry_confidence_fields():
    r = scanner.run_scan("sim-host", profile="standard")
    for p in r["ports"]:
        assert "seen_by" in p and p["confidence"] in ("confirmed", "single-engine")

def test_result_has_nuclei_list():
    r = scanner.run_scan("sim-host", profile="standard")
    assert isinstance(r["nuclei"], list)

def test_backward_compatible_keys_present():
    r = scanner.run_scan("sim-host", profile="quick")
    assert set(["target","profile","credential_checks","resolved_host",
                "ports","summary","engine"]).issubset(r)

def test_discovery_merges_sweeper_only_port(monkeypatch):
    # a port only the sweeper saw still appears, single-engine
    ...  # monkeypatch port_sweep.sweep + available_sweeper; assert seen_by==["rustscan"]
```
- [ ] **Step 2: Run to verify it fails** → FAIL (missing keys)
- [ ] **Step 3: Implement.** In `_real_scan`: if `port_sweep.available_sweeper()` is not None, sweep `profile_cfg["sweep_range"]`, seed `seen_by` per discovered port, and run nmap `-sV -p <csv>` over the discovered set; else keep today's `--top-ports` phase. Add `nmap` to `seen_by` for every port nmap confirms; set `confidence` from `len(seen_by)`. After the script phase, call `nuclei_scan.run_nuclei(...)` (gated by config) and attach `result["nuclei"]` plus `scripts["nuclei:<id>"]` on matched ports. In `_simulate_scan`: populate `seen_by`/`confidence` (sometimes multi-engine) and set `result["nuclei"] = nuclei_scan.simulate_nuclei(...)`. Poll `cancel_check` before the nuclei stage.
- [ ] **Step 4: Run to verify it passes** → PASS, plus `pytest tests/test_real_engine.py -v` still green.
- [ ] **Step 5: Commit**

---

### Task 5: Nuclei penalties in scoring

**Files:**
- Modify: `backend/services/scoring.py`
- Test: `backend/tests/test_scoring.py` (add cases)

**Interfaces:**
- Consumes: `result["nuclei"]` (Task 4).
- Produces: `compute_risk(ports, credential_checks=None, nuclei=None) -> {score, grade, breakdown}` (new optional `nuclei` param; existing callers unaffected). New constants `NUCLEI_SEVERITY_PENALTY = {"critical":25,"high":18,"medium":8,"low":3,"info":0}`, `NUCLEI_PENALTY_CAP = 45`.

- [ ] **Step 1: Write the failing test**
```python
import scoring

def test_nuclei_findings_deduct_points():
    base = scoring.compute_risk([], None)["score"]
    with_f = scoring.compute_risk([], None,
        nuclei=[{"severity": "critical"}])["score"]
    assert with_f < base

def test_nuclei_penalty_capped_and_nonnegative():
    many = [{"severity": "critical"}] * 20
    r = scoring.compute_risk([], None, nuclei=many)
    assert r["score"] >= 0
    cap_line = [b for b in r["breakdown"] if "nuclei" in b["reason"].lower()][0]
    assert -cap_line["points"] <= scoring.NUCLEI_PENALTY_CAP
```
- [ ] **Step 2: Run to verify it fails** → FAIL (TypeError / no nuclei line)
- [ ] **Step 3: Implement** the optional param and a capped, severity-weighted deduction emitted as an auditable breakdown line referencing the counts by severity (reuse the existing `add_capped` helper).
- [ ] **Step 4: Run to verify it passes** → PASS, plus full `pytest tests/test_scoring.py tests/test_ground_truth.py -v` green.
- [ ] **Step 5: Commit**

---

### Task 6: Nuclei findings in CVE intel

**Files:**
- Modify: `backend/services/cve_intel.py`
- Test: `backend/tests/test_cve_intel.py` (add cases)

**Interfaces:**
- Consumes: `result["nuclei"]` (Task 4).
- Produces: `enrich(ports, credential_checks=None, nuclei=None)` (new optional param) adds tool-confirmed entries (highest confidence) carrying the template `reference`/CVE and `cvss`.

- [ ] **Step 1: Write the failing test**
```python
import cve_intel

def test_nuclei_findings_become_confirmed_intel():
    findings = cve_intel.enrich([], None,
        nuclei=[{"template_id":"apache-cve-2021-41773","severity":"critical",
                 "reference":["CVE-2021-41773"]}])
    assert any(f.get("confidence") == "confirmed" for f in findings)
```
- [ ] **Step 2: Run to verify it fails** → FAIL
- [ ] **Step 3: Implement** the optional param mapping nuclei findings into the existing finding shape with `confidence="confirmed"`.
- [ ] **Step 4: Run to verify it passes** → PASS
- [ ] **Step 5: Commit**

---

### Task 7: Enrichment wiring

**Files:**
- Modify: `backend/services/scan_service.py` (`_enrich`)
- Test: `backend/tests/test_api_flow.py` (add assertion) or extend `test_scanner_pipeline.py`

**Interfaces:**
- Consumes: `result["nuclei"]` (Task 4), `scoring.compute_risk(..., nuclei=)` (Task 5), `cve_intel.enrich(..., nuclei=)` (Task 6).
- Produces: a completed scan whose `risk` and `intel` reflect nuclei findings.

- [ ] **Step 1: Write the failing test** — a full simulated scan through the API exposes nuclei in stored result and the breakdown includes a nuclei line when findings exist.
- [ ] **Step 2: Run to verify it fails** → FAIL
- [ ] **Step 3: Implement** `_enrich` to pass `scan_result.get("nuclei")` into `scoring.compute_risk` and `cve_intel.enrich`.
- [ ] **Step 4: Run to verify it passes** → PASS, plus `pytest tests/test_api_flow.py -v` green.
- [ ] **Step 5: Commit**

---

### Task 8: Differential & ground-truth coverage

**Files:**
- Modify: `backend/tests/differential/harness.py` (add production-discovery agreement check)
- Modify: `backend/tests/ground_truth/harness.py` or `tests/test_ground_truth.py` (nuclei flags lab Apache 2.4.49)
- Test: the harness files themselves

**Interfaces:**
- Consumes: `port_sweep.sweep` (Task 2), the independent oracle in `independent_scanner.py`.

- [ ] **Step 1: Write the failing check** — assert production `port_sweep` discovery (when a sweeper is present) agrees with the independent socket oracle on the lab; a ground-truth expectation that a nuclei run flags CVE-2021-41773 on the lab's Apache box. Both skip cleanly when the tool/lab is absent.
- [ ] **Step 2: Run to verify it fails (or skips when tools absent)** — `pytest tests/test_differential.py tests/test_ground_truth.py -v`
- [ ] **Step 3: Implement** the checks, keeping `independent_scanner.py` free of production imports.
- [ ] **Step 4: Run to verify it passes/skips** → green
- [ ] **Step 5: Commit**

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`, `.env.example`, `docs/ARCHITECTURE.md`, `CHANGELOG.md`

**Interfaces:** none (docs only).

- [ ] **Step 1:** Update `README.md` — extend the feature table and add a subsection describing the discovery→detection pipeline, the `seen_by`/`confidence` field, nuclei integration, and the NSE expansion, stating **why each was added** (coverage / accuracy / confirmed findings) and documenting the silent-degradation behavior and every new env var.
- [ ] **Step 2:** Add the new env vars with explanatory comments to `.env.example`.
- [ ] **Step 3:** Document the pipeline stages and new modules (`port_sweep.py`, `nuclei_scan.py`) in `docs/ARCHITECTURE.md`.
- [ ] **Step 4:** Add a dated `CHANGELOG.md` entry.
- [ ] **Step 5:** Verify the full suite — `cd backend && python -m pytest -q` → all green. Commit.

---

## Self-Review

**Spec coverage:** §3.1 pipeline → Tasks 2,4; §3.2 confidence → Task 4; §3.3 nuclei → Tasks 3,4; §3.4 NSE expansion → Task 4 (bundle) + Task 5 (scoring of new families); §3.5 scoring/intel → Tasks 5,6,7; §3.6 config/profiles → Task 1; §3.7 simulation → Tasks 3,4; §6 testing → every task + Task 8; §7 documentation → Task 9. All sections mapped.

**Review Focus:** each of the five lines has an owning task with a test (empty sweep → Task 2; malformed JSONL → Task 3; unfingerprinted port + backward-compat → Task 4; cap/nonnegative → Task 5).

**Type consistency:** `seen_by: list[str]`, `confidence: str`, `result["nuclei"]: list[dict]`, and the `nuclei=` param name are used identically across Tasks 4–7. Finding dict keys (`template_id, severity, reference, cvss`) match between Task 3 producer and Tasks 5/6 consumers.

**Proportion:** plan is close to the spec's length; code blocks are test names/assertions and signatures, not implementations.
