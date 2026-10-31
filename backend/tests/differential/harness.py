"""Differential validation harness for PortWatch Pro.

Judges PortWatch's REAL engine against an independent oracle (a plain-socket
prober, and a second external scanner when one is installed) over the reference
lab in docker/lab/. Unlike the ground-truth harness, nothing here is derived
from PortWatch's own output or from the simulation: the oracle connects to the
same hosts with different code, so agreement is evidence.

For each lab host it measures:
  * Port detection  - PortWatch's open set vs the independent oracle's open set,
                      over the candidate port universe (expected + decoys).
  * Lab integrity   - the oracle's open set vs the manifest's declared intent.
                      A mismatch means the lab is broken or still booting, not
                      that PortWatch is wrong, so it is reported separately.
  * CVE detection   - whether the deliberately vulnerable host's expected
                      http-vuln-* flags actually fired.
  * Service identity - whether the scanner's version string matches intent.

Run against a live lab with scanner.run_scan passed in. See report.py for the
markdown writer and test_differential.py for the pytest gate.
"""

import json
import os

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "lab_manifest.json")


def load_manifest(path=None):
    with open(path or MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def candidate_universe(manifest):
    """Every port the oracle should probe: all declared open ports + decoys."""
    ports = set(manifest.get("decoy_ports", []))
    for host in manifest["hosts"]:
        ports.update(host["open_ports"])
    return sorted(ports)


def _portwatch_view(run_scan, address, profile):
    """Run PortWatch's engine and pull out the facts the harness compares."""
    result = run_scan(address, profile=profile, simulate=False)
    open_ports = {p["port"] for p in result["ports"] if p.get("state") == "open"}
    vuln_flags = sorted({
        name
        for p in result["ports"]
        for name, out in (p.get("scripts") or {}).items()
        if name.startswith("http-vuln-") and out and "VULNERABLE" in str(out).upper()
    })
    versions = {
        p["port"]: (p.get("version") or p.get("service") or "")
        for p in result["ports"] if p.get("state") == "open"
    }
    return {
        "engine": result.get("engine"),
        "open_ports": open_ports,
        "vuln_flags": vuln_flags,
        "versions": versions,
    }


def evaluate(run_scan, probe_ports, external_scan=None, manifest=None, profile=None):
    """Run the whole lab through PortWatch and the oracle; return a result dict.

    run_scan:    scanner.run_scan (PortWatch's real engine).
    probe_ports: independent_scanner.probe_ports (the always-on oracle).
    external_scan: independent_scanner.external_scan or None (second opinion).
    """
    manifest = manifest or load_manifest()
    profile = profile or manifest.get("profile", "deep")
    universe = candidate_universe(manifest)

    hosts_out = []
    pw_tp = pw_fp = pw_fn = 0           # PortWatch vs oracle, over the universe
    vuln_expected = vuln_found = 0
    svc_expected = svc_correct = 0
    lab_integrity_failures = []
    external_name = None

    for host in manifest["hosts"]:
        addr = host["address"]
        intent = set(host["open_ports"])

        oracle = probe_ports(addr, universe)
        ext = external_scan(addr, universe) if external_scan else None
        if ext is not None:
            external_name = True

        # Lab integrity: does reality match what we meant to expose?
        if oracle != intent:
            lab_integrity_failures.append({
                "host": host["name"],
                "declared": sorted(intent),
                "observed": sorted(oracle),
                "missing": sorted(intent - oracle),
                "unexpected": sorted(oracle - intent),
            })

        pw = _portwatch_view(run_scan, addr, profile)
        pw_in_universe = pw["open_ports"] & set(universe)

        tp = len(pw_in_universe & oracle)
        fp = len(pw_in_universe - oracle)
        fn = len(oracle - pw_in_universe)
        pw_tp += tp
        pw_fp += fp
        pw_fn += fn

        # CVE detection on the host that should have a confirmed vuln.
        exp_flags = set(host.get("expected_vuln_flags", []))
        got_flags = set(pw["vuln_flags"])
        vuln_expected += len(exp_flags)
        vuln_found += len(exp_flags & got_flags)

        # Service identity: expected_service substring in any open-port version.
        svc_ok = None
        want = host.get("expected_service")
        if want:
            svc_expected += 1
            blob = " ".join(pw["versions"].values()).lower()
            svc_ok = want.lower() in blob
            if host.get("expected_version_contains"):
                svc_ok = svc_ok and host["expected_version_contains"].lower() in blob
            if svc_ok:
                svc_correct += 1

        hosts_out.append({
            "host": host["name"],
            "address": addr,
            "engine": pw["engine"],
            "declared_open": sorted(intent),
            "oracle_open": sorted(oracle),
            "external_open": (sorted(ext) if ext is not None else None),
            "portwatch_open": sorted(pw["open_ports"]),
            "portwatch_open_in_universe": sorted(pw_in_universe),
            "missing_vs_oracle": sorted(oracle - pw_in_universe),
            "extra_vs_oracle": sorted(pw_in_universe - oracle),
            "portwatch_unverified_open": sorted(pw["open_ports"] - set(universe)),
            "expected_vuln_flags": sorted(exp_flags),
            "found_vuln_flags": sorted(got_flags),
            "vuln_ok": exp_flags.issubset(got_flags),
            "expected_service": want,
            "service_ok": svc_ok,
            "versions": pw["versions"],
        })

    def ratio(num, den):
        return round(num / den, 4) if den else 1.0

    return {
        "profile": profile,
        "candidate_universe": universe,
        "n_hosts": len(manifest["hosts"]),
        "external_scanner_used": bool(external_name),
        "port_detection_vs_oracle": {
            "precision": ratio(pw_tp, pw_tp + pw_fp),
            "recall": ratio(pw_tp, pw_tp + pw_fn),
            "true_positives": pw_tp,
            "false_positives": pw_fp,
            "false_negatives": pw_fn,
        },
        "cve_detection": {
            "expected": vuln_expected,
            "found": vuln_found,
            "recall": ratio(vuln_found, vuln_expected),
        },
        "service_identity": {
            "expected": svc_expected,
            "correct": svc_correct,
            "accuracy": ratio(svc_correct, svc_expected),
        },
        "lab_integrity": {
            "ok": not lab_integrity_failures,
            "failures": lab_integrity_failures,
        },
        "hosts": hosts_out,
    }
