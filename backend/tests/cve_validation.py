"""Validate PortWatch's offline CVE knowledge base against external truth.

Two independent checks, neither of which trusts the KB's own say-so:

  * Internal consistency (offline, always available): every CVE the KB asserts
    carries a CVSS score and a severity label. The label must match the band the
    score falls in. A KB that calls a 9.0 "high" is wrong about its own data.

  * NVD cross-check (online, gated): for each CVE, fetch the authoritative record
    from the NVD 2.0 API and compare the KB's CVSS and severity to NVD's. This is
    the independent oracle for the CVE layer - it shares no data with PortWatch.

The regex version-range boundaries are validated separately, by the probe tables
in test_cve_intel.py (positive/negative banner cases authored from each CVE's
fixed version).
"""

import json
import os
import sys
import urllib.request
import urllib.error

try:
    import cve_intel
except ModuleNotFoundError:  # running as a script, not under pytest's app wiring
    _BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    for _p in (_BACKEND, os.path.join(_BACKEND, "services")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    import cve_intel

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def band_for_cvss(score):
    """CVSS v3.1 qualitative band for a base score."""
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def collect_kb_claims():
    """Every (cve, cvss, severity) the KB asserts, with where it came from."""
    claims = []
    for script, rec in cve_intel.NSE_CVE_MAP.items():
        for cve in rec["cve"]:
            claims.append({"cve": cve, "cvss": rec["cvss"],
                           "severity": rec["severity"], "source": f"NSE:{script}"})
    for rec in cve_intel.VERSION_CVES:
        for cve in rec["cve"]:
            claims.append({"cve": cve, "cvss": rec["cvss"],
                           "severity": rec["severity"], "source": f"version:{rec['title'][:40]}"})
    return claims


def check_internal_consistency(claims=None):
    """Return the claims whose severity label disagrees with their CVSS band."""
    claims = claims if claims is not None else collect_kb_claims()
    problems = []
    for c in claims:
        band = band_for_cvss(c["cvss"])
        if band and c["severity"] != band:
            problems.append({**c, "expected_band": band})
    return problems


# ───────────────────────── NVD cross-check (online) ─────────────────────────

def fetch_nvd(cve, timeout=20):
    """Fetch one CVE's CVSS v3.1 base score + severity from NVD. Returns
    {"base_score", "severity"} or raises on network / parse failure."""
    req = urllib.request.Request(NVD_API + cve, headers={"User-Agent": "portwatch-cve-validation"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        raise LookupError(f"{cve} not found in NVD")
    metrics = vulns[0]["cve"].get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            cvss = metrics[key][0]["cvssData"]
            return {"base_score": cvss["baseScore"],
                    "severity": cvss["baseSeverity"].lower()}
    raise LookupError(f"{cve} has no CVSS v3 metric in NVD")


def cross_check_nvd(claims=None, tolerance=1.0):
    """Compare KB claims to NVD. Returns a report with per-CVE rows and a list
    of drifts (|KB cvss - NVD cvss| > tolerance, or severity band off by >1)."""
    claims = claims if claims is not None else collect_kb_claims()
    rows, drifts, errors = [], [], []
    order = ["none", "low", "medium", "high", "critical"]
    # De-dup by CVE (several KB entries can cite the same CVE).
    by_cve = {}
    for c in claims:
        by_cve.setdefault(c["cve"], c)
    for cve, c in sorted(by_cve.items()):
        try:
            nvd = fetch_nvd(cve)
        except (urllib.error.URLError, LookupError, KeyError, TimeoutError) as e:
            errors.append({"cve": cve, "error": str(e)})
            continue
        cvss_drift = abs((c["cvss"] or 0) - nvd["base_score"])
        band_gap = abs(order.index(band_for_cvss(c["cvss"]) or "none")
                       - order.index(nvd["severity"]))
        row = {"cve": cve, "kb_cvss": c["cvss"], "nvd_cvss": nvd["base_score"],
               "kb_severity": c["severity"], "nvd_severity": nvd["severity"],
               "cvss_drift": round(cvss_drift, 1), "band_gap": band_gap}
        rows.append(row)
        if cvss_drift > tolerance or band_gap > 1:
            drifts.append(row)
    return {"rows": rows, "drifts": drifts, "errors": errors,
            "checked": len(rows), "drift_count": len(drifts)}


if __name__ == "__main__":
    import sys
    probs = check_internal_consistency()
    print(f"Internal consistency: {len(probs)} problem(s)")
    for p in probs:
        print(f"  {p['cve']}: labelled {p['severity']} but CVSS {p['cvss']} is {p['expected_band']}")
    if "--nvd" in sys.argv:
        print("\nNVD cross-check (live)...")
        rep = cross_check_nvd()
        for r in rep["rows"]:
            flag = "  DRIFT" if r in rep["drifts"] else ""
            print(f"  {r['cve']}: KB {r['kb_cvss']}/{r['kb_severity']} vs "
                  f"NVD {r['nvd_cvss']}/{r['nvd_severity']}{flag}")
        for e in rep["errors"]:
            print(f"  {e['cve']}: ERROR {e['error']}")
        print(f"\n{rep['drift_count']} drift(s) over {rep['checked']} CVE(s) checked.")
