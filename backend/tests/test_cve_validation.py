"""CVE knowledge-base validation.

  * test_kb_internally_consistent - offline, always runs. Every CVE's severity
    label must match its own CVSS band.
  * test_kb_matches_nvd - online, gated behind PORTWATCH_NVD=1. Cross-checks the
    KB's CVSS/severity against the authoritative NVD record.

Regex version-range boundaries are covered by test_cve_intel.py.
"""

import os
import pytest

import cve_validation

NVD_ENABLED = os.environ.get("PORTWATCH_NVD") == "1"


def test_kb_internally_consistent():
    problems = cve_validation.check_internal_consistency()
    assert problems == [], (
        "CVE entries whose severity label disagrees with their CVSS band: "
        + "; ".join(f"{p['cve']} is '{p['severity']}' but CVSS {p['cvss']} "
                    f"=> '{p['expected_band']}'" for p in problems)
    )


@pytest.mark.skipif(not NVD_ENABLED,
                    reason="set PORTWATCH_NVD=1 to cross-check CVEs against the live NVD API")
def test_kb_matches_nvd():
    report = cve_validation.cross_check_nvd(tolerance=1.0)
    # Every CVE the KB asserts must actually exist in NVD.
    unknown = [e for e in report["errors"] if "not found" in e["error"]]
    assert not unknown, f"KB asserts CVEs absent from NVD: {unknown}"
    # Severity band must be within one step of NVD's; CVSS drift is reported but
    # a band gap of 2+ (e.g. calling a 'low' a 'critical') is a hard failure.
    bad = [d for d in report["drifts"] if d["band_gap"] >= 2]
    assert not bad, f"KB severity off by 2+ bands vs NVD: {bad}"
