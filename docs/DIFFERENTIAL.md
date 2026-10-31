# Differential Validation

`docs/VALIDATION.md` measures the scanner against a hand-authored corpus and the
simulation engine. That is a regression guard: the corpus was written from the
simulation's own documented behaviour, so it cannot catch a fault shared by both.
This document covers the **independent** check: PortWatch's real `nmap` engine
scanned against a lab of real services, judged by an oracle that shares none of
its code.

## What it proves

| Question | How it is answered |
|----------|--------------------|
| Does the real engine see the ports that are actually open? | A plain-socket prober (`backend/tests/differential/independent_scanner.py`) connects to the same hosts with no nmap and no PortWatch code. PortWatch's open set is compared against it. |
| Is the lab itself trustworthy? | The oracle's open set is compared to the manifest's declared intent. If they disagree, the lab is broken or still booting and the run fails loudly before judging PortWatch. |
| Does the engine catch a real CVE, not just a simulated one? | The lab runs Apache 2.4.49 in the exploitable configuration for CVE-2021-41773; the live NSE script must flag it. |
| Does version detection work against real banners? | Each host declares an expected service string the scan must match. |
| Is there a second opinion? | When RustScan, naabu or masscan is installed, it is run as a second independent scanner and its open set is reported alongside the socket oracle. |

The one thing it deliberately does **not** do is trust PortWatch's output as its
own reference. The oracle is the reference.

## The reference lab

`docker/lab/docker-compose.lab.yml` publishes six services, each on its native
port on a distinct `127.0.0.0/8` loopback address so it looks like its own host
and so scanning it is authorised by construction (it is your own machine):

| Host | Address | Port | State |
|------|---------|------|-------|
| clean-web | 127.0.0.11 | 80 | Hardened nginx: all security headers, GET/HEAD only |
| apache-vuln | 127.0.0.12 | 80 | Apache 2.4.49, exploitable for CVE-2021-41773 |
| redis-open | 127.0.0.13 | 6379 | Unauthenticated Redis |
| mongo-open | 127.0.0.14 | 27017 | No-auth MongoDB |
| postgres-exposed | 127.0.0.15 | 5432 | Exposed PostgreSQL |
| ftp-plain | 127.0.0.16 | 21 | Plaintext FTP |

`backend/tests/differential/lab_manifest.json` is the machine-readable intent and
must stay in sync with the compose file (`test_differential.py` asserts it).

> The `127.0.0.N` host addresses work as published addresses on Linux, where CI
> runs. On macOS/Windows the whole of `127.0.0.0/8` is not loopback by default;
> run the lab and harness inside the Docker network there, or just rely on the
> Linux CI job, which is the authoritative run.

## Running it locally (Linux)

```bash
docker compose -f docker/lab/docker-compose.lab.yml up -d
cd backend
PORTWATCH_LAB=1 python -m pytest tests/test_differential.py -q   # the gate
python tests/differential/report.py                              # the report
docker compose -f ../docker/lab/docker-compose.lab.yml down -v
```

`report.py` writes `backend/tests/differential/report.{md,json}`. Every number is
derived from a fresh scan plus an independent probe, so a third party can
reproduce it.

## In CI

`.github/workflows/ci.yml` has a `differential` job that installs nmap, brings the
lab up, waits for every declared port to accept a connection, runs the gate with
`PORTWATCH_LAB=1`, and uploads the report as an artifact. The gate asserts:

- **recall == 1.0** against the oracle (no open port is missed),
- **0 false positives** within the probed universe (no closed port called open),
- **CVE recall == 1.0** (the planted CVE-2021-41773 is caught).

## Relationship to the CVE knowledge base check

The `cve-nvd` CI job (`backend/tests/cve_validation.py`) is the other independent
check: it cross-checks every CVE PortWatch asserts against the authoritative NVD
record for CVSS and severity, and the regex version boundaries are pinned by the
positive/negative banner tables in `test_cve_intel.py`. Together with this
differential run, that covers the three things the scanner claims and previously
only self-certified: the ports, the CVEs, and the risk rank.
