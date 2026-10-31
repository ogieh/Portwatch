"""Render the differential harness result as a markdown report.

Run directly to scan the live lab and print the report:
    cd backend
    python -m pytest tests/test_differential.py -q      # gate (needs live lab)
    python tests/differential/report.py                 # human-readable report

Every number is derived from a fresh scan plus an independent socket probe, so a
third party can reproduce it by bringing up the lab and re-running.
"""

import os
import sys
import json

# Mirror app.py's import wiring so bare `import scanner` resolves to the
# canonical services/ module (the top-level duplicates have been removed).
_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_BACKEND, os.path.join(_BACKEND, "services")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
sys.path.remove(os.path.join(_BACKEND, "services"))
sys.path.insert(0, os.path.join(_BACKEND, "services"))

import scanner  # PortWatch's real engine (services/scanner.py)
from tests.differential import harness, independent_scanner


def build_result():
    return harness.evaluate(
        run_scan=scanner.run_scan,
        probe_ports=independent_scanner.probe_ports,
        external_scan=independent_scanner.external_scan,
    )


def render(result):
    lines = []
    w = lines.append
    w("# Differential Validation Report")
    w("")
    w("PortWatch's real engine judged against an independent oracle (a plain-")
    w("socket prober" + (", plus an external scanner" if result["external_scanner_used"] else "")
      + ") over the reference lab in `docker/lab/`. No number here comes from")
    w("PortWatch's own output or from the simulation engine.")
    w("")
    w(f"- Profile: `{result['profile']}`")
    w(f"- Hosts: {result['n_hosts']}")
    w(f"- Candidate port universe: {result['candidate_universe']}")
    w(f"- External second scanner used: {'yes' if result['external_scanner_used'] else 'no (socket oracle only)'}")
    w("")

    li = result["lab_integrity"]
    w("## Lab integrity (oracle vs declared intent)")
    w("")
    if li["ok"]:
        w("All hosts expose exactly the ports the manifest declares. The lab is a")
        w("sound oracle for this run.")
    else:
        w("**Lab integrity FAILED** - the oracle disagrees with the manifest, so")
        w("the lab is broken or still booting. PortWatch results below are suspect.")
        w("")
        for f in li["failures"]:
            w(f"- `{f['host']}`: declared {f['declared']}, observed {f['observed']}"
              f" (missing {f['missing']}, unexpected {f['unexpected']})")
    w("")

    pd = result["port_detection_vs_oracle"]
    w("## Port detection: PortWatch vs independent oracle")
    w("")
    w("| Metric | Value |")
    w("|---|---|")
    w(f"| Precision | {pd['precision']} |")
    w(f"| Recall | {pd['recall']} |")
    w(f"| True positives | {pd['true_positives']} |")
    w(f"| False positives | {pd['false_positives']} |")
    w(f"| False negatives | {pd['false_negatives']} |")
    w("")

    cve = result["cve_detection"]
    w("## CVE detection (live NSE scripts)")
    w("")
    w(f"Expected vulnerability flags found: **{cve['found']} / {cve['expected']}** "
      f"(recall {cve['recall']}).")
    w("")

    svc = result["service_identity"]
    w("## Service identity")
    w("")
    w(f"Correct service identification: **{svc['correct']} / {svc['expected']}** "
      f"(accuracy {svc['accuracy']}).")
    w("")

    w("## Per-host detail")
    w("")
    w("| Host | Oracle open | PortWatch open | Missing | Extra | Unverified | CVE | Service |")
    w("|---|---|---|---|---|---|---|---|")
    for h in result["hosts"]:
        ext = "" if h["external_open"] is None else f" (ext {h['external_open']})"
        w("| {host} | {oracle}{ext} | {pw} | {miss} | {extra} | {unv} | {cve} | {svc} |".format(
            host=h["host"],
            oracle=h["oracle_open"], ext=ext,
            pw=h["portwatch_open_in_universe"],
            miss=h["missing_vs_oracle"] or "-",
            extra=h["extra_vs_oracle"] or "-",
            unv=h["portwatch_unverified_open"] or "-",
            cve=("ok" if h["vuln_ok"] else f"MISS {h['expected_vuln_flags']}")
                if h["expected_vuln_flags"] else "-",
            svc=("ok" if h["service_ok"] else "MISS") if h["expected_service"] else "-",
        ))
    w("")
    w("## How to reproduce")
    w("")
    w("```")
    w("docker compose -f docker/lab/docker-compose.lab.yml up -d")
    w("cd backend && python tests/differential/report.py")
    w("docker compose -f docker/lab/docker-compose.lab.yml down")
    w("```")
    w("")
    return "\n".join(lines)


def main():
    result = build_result()
    out_md = os.path.join(os.path.dirname(__file__), "report.md")
    out_json = os.path.join(os.path.dirname(__file__), "report.json")
    text = render(result)
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(text)
    print(f"\nWrote {out_md} and {out_json}")


if __name__ == "__main__":
    main()
