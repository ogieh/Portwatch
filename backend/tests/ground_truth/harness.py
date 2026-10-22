"""Ground-truth validation harness for PortWatch Pro.

Compares scan output against a labeled reference corpus (corpus.json) and
reports, per target: port-detection precision/recall, vuln-flag TP/FP, and
score-vs-expert calibration. A corpus whose ground truth is wrong is a broken
harness, so every expected value must be independently confirmable from the
raw scan record -- never asserted from the scanner's own claim.
"""

import json
import os

import scoring

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "corpus.json")


def _load_corpus():
    with open(CORPUS_PATH) as fh:
        return json.load(fh)


def _scan(target, scanner, profile):
    """Run the scanner and normalise its output into the harness's view."""
    result = scanner(target, profile=profile)
    open_ports = sorted(p["port"] for p in result["ports"] if p["state"] == "open")
    vulns = sorted(
        (p["port"], n)
        for p in result["ports"]
        for n, out in p["scripts"].items()
        if n.startswith("http-vuln-") and out and "VULNERABLE" in str(out).upper()
    )
    risk = scoring.compute_risk(result["ports"], result.get("credential_checks"))
    return {
        "target": result.get("target", target),
        "open_ports": open_ports,
        "vuln_flags": [n for _, n in vulns],
        "vuln_hits": vulns,
        "score": risk["score"],
        "grade": risk["grade"],
        "breakdown": risk["breakdown"],
        "scripts_error": result.get("scripts_error"),
    }


def _band_ok(score, band, min_score):
    """Score must clear the expert's minimum and land in the letter band."""
    if score < min_score:
        return False
    letters = band.split("-")
    return letters[0] <= grade_for_letter(score) <= letters[-1]


def grade_for_letter(score):
    for threshold, letter in scoring.GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def evaluate(scanner, profile="standard", corpus_path=None):
    """Run every corpus target through the scanner and measure agreement."""
    corpus = _load_corpus() if corpus_path is None else json.load(open(corpus_path))
    port_tp = port_fp = port_fn = 0
    vuln_tp = vuln_fp = vuln_fn = 0
    calibration_failures = []
    disagreements = []

    for target in corpus["targets"]:
        exp = target["expected"]
        got = _scan(target["name"], scanner, profile)

        # Port detection: precision/recall over the open-port set.
        exp_ports = set(exp["open_ports"])
        got_ports = set(got["open_ports"])
        tp = len(exp_ports & got_ports)
        port_tp += tp
        port_fp += len(got_ports - exp_ports)
        port_fn += len(exp_ports - got_ports)

        # Vuln flags: TP/FP over the flagged script names.
        exp_vulns = set(exp["vuln_flags"])
        got_vulns = set(got["vuln_flags"])
        vuln_tp += len(exp_vulns & got_vulns)
        vuln_fp += len(got_vulns - exp_vulns)
        vuln_fn = len(exp_vulns - got_vulns)

        # Score calibration: does the score land in the expert band?
        band_ok = _band_ok(got["score"], exp["grade_band"], exp["min_score"])
        if not band_ok:
            calibration_failures.append({
                "target": target["name"], "score": got["score"],
                "band": exp["grade_band"],
            })

        disagreements.append({
            "target": target["name"],
            "expert_severity": target["expert_severity"],
            "open_ports": {
                "expected": sorted(exp_ports), "actual": sorted(got_ports),
                "missing": sorted(exp_ports - got_ports),
                "extra": sorted(got_ports - exp_ports),
            },
            "vuln_flags": {
                "expected": sorted(exp_vulns), "actual": sorted(got_vulns),
                "missing": sorted(exp_vulns - got_vulns),
                "extra": sorted(got_vulns - exp_vulns),
            },
            "score": got["score"],
            "grade": got["grade"],
            "grade_band": exp["grade_band"],
            "band_ok": band_ok,
        })

    n = len(corpus["targets"])
    port_prec = port_tp / (port_tp + port_fp) if (port_tp + port_fp) else 1.0
    port_rec = port_tp / (port_tp + port_fn) if (port_tp + port_fn) else 1.0
    vuln_prec = vuln_tp / (vuln_tp + vuln_fp) if (vuln_tp + vuln_fp) else 1.0
    vuln_rec = vuln_tp / (vuln_tp + vuln_fn) if (vuln_tp + vuln_fn) else 1.0
    return {
        "corpus": corpus_path or CORPUS_PATH,
        "profile": profile,
        "n_targets": n,
        "port_detection": {
            "precision": round(port_prec, 4),
            "recall": round(port_rec, 4),
            "true_positives": port_tp,
            "false_positives": port_fp,
            "false_negatives": port_fn,
        },
        "vuln_flags": {
            "precision": round(vuln_prec, 4),
            "recall": round(vuln_rec, 4),
            "true_positives": vuln_tp,
            "false_positives": vuln_fp,
            "false_negatives": vuln_fn,
        },
        "calibration": {
            "in_band": n - len(calibration_failures),
            "out_of_band": len(calibration_failures),
            "failures": calibration_failures,
        },
        "disagreements": disagreements,
        "rank_calibration": rank_calibration(disagreements),
    }


# ───────────────────────── RANK CALIBRATION ─────────────────────────
# The score is a mechanical model (count of exposed ports, minus script
# penalties). An expert weighs service criticality, not just port count, so
# the two will not always agree. The harness measures the gap instead of
# hiding it: Spearman rank correlation plus the list of inversions.

def _rank(values):
    """Average ranks for ties, 1-based."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman(xs, ys):
    """Spearman rank correlation. +1 = perfect agreement, 0 = unrelated."""
    if len(xs) < 2:
        return 1.0
    rx, ry = _rank(xs), _rank(ys)
    n = len(xs)
    d2 = sum((a - b) ** 2 for a, b in zip(rx, ry))
    return 1 - (6.0 * d2) / (n * (n * n - 1))


def find_inversions(rows):
    """Pairs where a less severe host scores worse than a more severe one.

    rows: [{"target", "expert_severity", "score"}], best-effort sorted by
    severity ascending. Returns [{"more_severe", "less_severe", "gap"}].
    """
    ordered = sorted(rows, key=lambda r: r["expert_severity"])
    inversions = []
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            more, less = ordered[i], ordered[j]
            if less["score"] > more["score"]:
                inversions.append({
                    "more_severe": more["target"],
                    "more_severe_score": more["score"],
                    "less_severe": less["target"],
                    "less_severe_score": less["score"],
                    "gap": less["score"] - more["score"],
                })
    return inversions


def rank_calibration(disagreements):
    """Spearman correlation + inversion list over the corpus."""
    rows = [{"target": d["target"], "expert_severity": d["expert_severity"],
             "score": d["score"]} for d in disagreements]
    sev = [r["expert_severity"] for r in rows]
    sc = [r["score"] for r in rows]
    inv = find_inversions(rows)
    return {
        "spearman": round(spearman(sev, sc), 4),
        "inversions": inv,
        "inversion_count": len(inv),
        "note": (
            "Spearman is computed between expert severity and risk score, "
            "so a strongly NEGATIVE value is the expected sign: a more "
            "severe host must score lower. Inversions are pairs where that "
            "ordering breaks. They are a known limitation of the count-based "
            "model (it weighs port count, not service criticality), not a "
            "corpus error."
        ),
    }
