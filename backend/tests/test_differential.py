"""Differential validation tests.

Two layers:
  * test_manifest_matches_compose - cheap, always runs. Guards that the lab
    manifest and the docker-compose lab file stay in sync, so the oracle's
    "declared intent" really reflects what the lab exposes.
  * test_differential_against_oracle - the live run. Gated behind PORTWATCH_LAB=1
    and a real nmap install, because it needs the lab containers up. It scans
    the lab with PortWatch's real engine and asserts agreement with an
    independent socket oracle: no missed ports, and the planted CVE is caught.

Bring the lab up first:
    docker compose -f docker/lab/docker-compose.lab.yml up -d
"""

import os
import re
import sys

import pytest

HERE = os.path.dirname(__file__)
BACKEND = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(BACKEND, ".."))
COMPOSE = os.path.join(REPO, "docker", "lab", "docker-compose.lab.yml")

if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from tests.differential import harness, independent_scanner  # noqa: E402

LAB_ENABLED = os.environ.get("PORTWATCH_LAB") == "1"


def _compose_pairs():
    """Parse the compose file for (ip, container_port) published pairs."""
    text = open(COMPOSE, encoding="utf-8").read()
    pairs = set()
    # Matches lines like:   - "127.0.0.13:6379:6379"
    for m in re.finditer(r'"(\d+\.\d+\.\d+\.\d+):(\d+):(\d+)"', text):
        ip, _hostport, container = m.group(1), m.group(2), m.group(3)
        pairs.add((ip, int(container)))
    return pairs


def _manifest_pairs(manifest):
    pairs = set()
    for host in manifest["hosts"]:
        for port in host["open_ports"]:
            pairs.add((host["address"], int(port)))
    return pairs


def test_manifest_matches_compose():
    """The manifest's (address, port) intent must equal the compose file's
    published (address, container-port) pairs. If they drift, the oracle is
    validating against a lab that no longer exists."""
    manifest = harness.load_manifest()
    assert _manifest_pairs(manifest) == _compose_pairs(), (
        "lab_manifest.json and docker-compose.lab.yml disagree on exposed ports"
    )


@pytest.mark.skipif(not LAB_ENABLED,
                    reason="set PORTWATCH_LAB=1 and bring up docker/lab to run")
def test_differential_against_oracle():
    import scanner  # PortWatch's real engine

    if not scanner.nmap_available():
        pytest.skip("nmap binary not available; differential run needs the real engine")

    result = harness.evaluate(
        run_scan=scanner.run_scan,
        probe_ports=independent_scanner.probe_ports,
        external_scan=independent_scanner.external_scan,
    )

    # The lab must be a sound oracle: what we declared is what is actually open.
    assert result["lab_integrity"]["ok"], (
        "lab integrity failed (containers down or still booting): "
        f"{result['lab_integrity']['failures']}"
    )

    pd = result["port_detection_vs_oracle"]
    # No missed ports: the real engine must see every port the oracle sees.
    assert pd["recall"] == 1.0, f"PortWatch missed ports vs oracle: {pd}"
    # No phantom ports within the probed universe.
    assert pd["false_positives"] == 0, f"PortWatch reported closed ports as open: {pd}"

    # The deliberately-planted CVE must be caught by the live NSE scripts.
    cve = result["cve_detection"]
    assert cve["recall"] == 1.0, f"planted CVE not detected: {cve}"
