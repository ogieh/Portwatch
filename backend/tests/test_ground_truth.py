"""Ground-truth validation harness: scan output vs. a labeled reference corpus.

The corpus (tests/ground_truth/corpus.json) is the labelled reference set --
its expected values are the analyst's ground truth, not the scanner's claim.
This suite measures agreement and fails loudly if the engine drifts from it:

  * port detection precision/recall  (open-port set vs. expected)
  * vuln-flag true/false positives   (flagged script vs. expected)
  * score calibration                 (score lands in the expert band)
  * rank calibration                  (severity-to-score ordering agreement)

It also emits a machine-readable report (tests/ground_truth/report.json) so
the results are reproducible by a third party from the scan record alone.
"""

import json
import os

import pytest

import services.scanner as scanner_mod
from ground_truth.harness import evaluate, _load_corpus

REPORT_PATH = os.path.join(os.path.dirname(__file__), "ground_truth", "report.json")
PROFILE = "standard"


def _sim(target, profile=PROFILE, credential_checks=False):
    return scanner_mod.run_scan(target, profile=profile, simulate=True,
                                credential_checks=credential_checks)


@pytest.fixture(scope="module")
def report():
    result = evaluate(_sim, profile=PROFILE)
    with open(REPORT_PATH, "w") as fh:
        json.dump(result, fh, indent=2)
    return result


def test_corpus_has_targets():
    corpus = _load_corpus()
    assert len(corpus["targets"]) >= 10
    for t in corpus["targets"]:
        assert set(t["expected"]) >= {"open_ports", "vuln_flags", "min_score", "grade_band"}
        assert t["expected"]["open_ports"], t["name"]
        assert 0 <= t["expert_severity"] <= 100, t["name"]


def test_port_detection_exact(report):
    """The open-port set must match the labeled reference exactly."""
    pd = report["port_detection"]
    assert pd["precision"] == 1.0, pd
    assert pd["recall"] == 1.0, pd
    assert pd["false_positives"] == 0, pd
    assert pd["false_negatives"] == 0, pd
    assert pd["true_positives"] > 0, pd


def test_vuln_flags_exact(report):
    """Flagged vuln scripts must match the labeled reference exactly."""
    vf = report["vuln_flags"]
    assert vf["precision"] == 1.0, vf
    assert vf["recall"] == 1.0, vf
    assert vf["false_positives"] == 0, vf
    assert vf["false_negatives"] == 0, vf


def test_score_calibration_in_band(report):
    """Every score must land in its expert-assigned band and clear its floor."""
    cal = report["calibration"]
    assert cal["out_of_band"] == 0, cal["failures"]
    assert cal["in_band"] == report["n_targets"]


def test_score_tracks_expert_severity(report):
    """Score must move opposite to expert severity, strongly and consistently.

    Spearman is measured between severity and score, so a strongly negative
    value is the expected sign. The threshold is deliberately loose: the
    count-based model is expected to invert a few near-tie pairs.
    """
    rc = report["rank_calibration"]
    assert rc["spearman"] <= -0.75, rc
    # Near-tie inversions (small gaps) are expected; large ones are not.
    large = [i for i in rc["inversions"] if i["gap"] >= 10]
    assert not large, large


def test_no_target_is_disagreement_free_by_accident(report):
    """Every corpus target must be exercised: an empty expectation set that
    hides a real finding would show up as a port recall failure."""
    assert report["n_targets"] == len(_load_corpus()["targets"])
    assert report["port_detection"]["true_positives"] > 0


def test_report_is_written(report):
    """The report is the reproducible artifact a third party reads."""
    assert os.path.exists(REPORT_PATH)
    with open(REPORT_PATH) as fh:
        saved = json.load(fh)
    assert saved["port_detection"] == report["port_detection"]
    assert saved["vuln_flags"] == report["vuln_flags"]
    assert saved["calibration"]["in_band"] == report["calibration"]["in_band"]
    assert saved["rank_calibration"]["spearman"] == report["rank_calibration"]["spearman"]
