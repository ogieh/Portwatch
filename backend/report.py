"""
Client-facing report generation for PortWatch.

Builds a standalone, print-styled HTML report from a stored scan record.
Served at GET /api/report/<id>; the browser's "Save as PDF" turns it into
a client-ready document with zero extra server dependencies.

Deliberately light-themed: this page is meant for paper/PDF, unlike the
dark operator UI. Structure follows the usual engagement-report shape:

    cover meta -> executive summary -> scope & methodology ->
    findings (summary table + detail cards with remediation) ->
    priority roadmap -> framework mapping -> credential checks ->
    appendices (ports manifest, score breakdown) -> limitations
"""

from datetime import datetime
from html import escape

from findings import build_findings, passed_checks

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}

PROFILE_SCOPE = {
    "quick": "the 1,000 most common ports were NOT all covered; this profile "
             "samples the top 20 and skips script-based checks",
    "standard": "the 100 most common ports, plus SSL/HTTP script checks on "
                "discovered web services",
    "deep": "the 1,000 most common ports, plus SSL/HTTP script checks and "
            "extended timeouts",
}


def _esc(value):
    return escape(str(value if value is not None else "—"))


def _fmt_ts(ts):
    try:
        return datetime.fromisoformat(ts).strftime("%d %B %Y at %H:%M UTC")
    except (TypeError, ValueError):
        return ts or ""


def _grade_color(letter):
    return {
        "A": "#15803D", "B": "#4D7C0F", "C": "#B45309",
        "D": "#C2410C", "F": "#B91C1C",
    }.get(letter, "#334155")


SEV_COLOR = {
    "critical": "#991B1B", "high": "#B91C1C", "medium": "#B45309", "low": "#64748B",
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ── sections ──────────────────────────────────────────────

def _exec_summary(record, findings):
    risk = record.get("risk") or {}
    grade = risk.get("grade", "?")
    score = risk.get("score")

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = []
    if score is not None:
        tone = {
            "A": "an overall strong posture", "B": "a generally sound posture with "
            "specific gaps", "C": "a posture with material weaknesses that warrant "
            "scheduled attention", "D": "a weak posture carrying real exposure",
            "F": "a posture with severe, immediately actionable exposure",
        }.get(grade, "the measured posture")
        lines.append(
            f"The assessed surface scored <strong>{score}/100 (grade {grade})</strong>, "
            f"indicating {tone}."
        )

    if findings:
        worst = [f["title"] for f in findings[:3]]
        lines.append(
            "<strong>" + str(len(findings)) + " finding(s)</strong> were identified "
            "(" + ", ".join(f"{n} {sev}" for sev, n in sorted(
                counts.items(), key=lambda kv: SEV_ORDER[kv[0]])) +
            "). The most significant: " + "; ".join(w.lower() if i else w
                                                    for i, w in enumerate(worst)) + "."
        )
    else:
        lines.append(
            "No issues requiring attention surfaced within the scope of this "
            "assessment. This is a point-in-time result; see limitations below."
        )

    cc = record.get("credential_checks")
    if cc is None:
        lines.append(
            "Credential and lockout behaviour was <em>not</em> part of this "
            "assessment; login-path resilience remains untested."
        )
    elif not (cc.get("http_login_findings") or cc.get("db_findings")):
        lines.append("No authentication endpoints or credential-protected "
                     "services were discovered to test.")

    summary_text = _esc(record.get("summary"))
    if summary_text:
        lines.append(f"<em>Scanner abstract:</em> {summary_text}")

    return "".join(f"<p>{l}</p>" for l in lines)


def _scope_section(record):
    profile = record.get("profile") or "standard"
    coverage = PROFILE_SCOPE.get(profile, PROFILE_SCOPE["standard"])
    cc = record.get("credential_checks")
    cred_line = (
        "Opt-in credential checks ran: a small number of deliberately failed "
        "logins probed throttling/lockout behaviour, and default-credential "
        "scripts ran against exposed database services."
        if (cc or {}).get("enabled") else
        "No active authentication attempts were made."
    )
    rows = [
        ("Target", record.get("target")),
        ("Resolved to", record.get("resolved_host")),
        ("Scan profile", profile.title()),
        ("Port coverage", coverage),
        ("Active testing", cred_line),
        ("Tools", f"PortWatch automated scanner (Nmap/NSE), scan #{record.get('id', '?')}"),
        ("Assessed on", _fmt_ts(record.get("timestamp"))),
    ]
    body = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in rows)
    return f"""<section>
      <h2>Scope &amp; Methodology</h2>
      <table class="kv">{body}</table>
      <p class="fine">This was a remote, unauthenticated assessment of the single
      target above. No exploitation was performed, no data was exfiltrated, and no
      denial-of-service techniques were used. Findings reflect the exact moment of
      scanning.</p>
    </section>"""


def _findings_summary_table(findings):
    if not findings:
        return """<section>
          <h2>Findings Summary</h2>
          <p class="empty">No findings within tested scope.</p>
        </section>"""
    rows = "".join(
        f"<tr><td class='mono'>{f['id']}</td>"
        f"<td><span class='sev' style='color:{SEV_COLOR[f['severity']]};"
        f"border-color:{SEV_COLOR[f['severity']]}'>{f['severity'].upper()}</span></td>"
        f"<td>{_esc(f['title'])}</td>"
        f"<td>{len(f['evidence'])}</td></tr>"
        for f in findings
    )
    return f"""<section>
      <h2>Findings Summary</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Instances</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def _finding_card(f):
    color = SEV_COLOR[f["severity"]]
    owasp = ""
    if f.get("owasp"):
        owasp = ("<div class='owasp'>OWASP Top 10 (2021): "
                 + ", ".join(_esc(o) for o in f["owasp"]) + "</div>")
    evidence = ""
    if f["evidence"]:
        items = "".join(f"<li>{_esc(e)}</li>" for e in f["evidence"])
        evidence = f"<h3>Evidence</h3><ul class='ev'>{items}</ul>"
    steps = "".join(f"<li>{_esc(s)}</li>" for s in f["remediation"])
    return f"""
    <article class="finding-card">
      <header>
        <span class="fid mono">{_esc(f['id'])}</span>
        <span class="sev" style="color:{color};border-color:{color}">{_esc(f['severity'].upper())}</span>
        <h3 class="ftitle">{_esc(f['title'])}</h3>
      </header>
      {owasp}
      <p>{_esc(f['description'])}</p>
      <h3>Impact</h3>
      <p>{_esc(f['impact'])}</p>
      {evidence}
      <h3>Remediation</h3>
      <ol class="fix">{steps}</ol>
    </article>"""


def _findings_detail(findings):
    cards = "".join(_finding_card(f) for f in findings)
    return f"""<section>
      <h2>Detailed Findings &amp; Remediation</h2>
      {cards or "<p class='empty'>Nothing to expand.</p>"}
    </section>"""


def _roadmap(findings):
    """One prioritised action per high-severity finding - the page most
    clients actually screenshot."""
    picks = [f for f in findings if SEV_ORDER[f["severity"]] <= 1] or findings[:3]
    if not picks:
        return ""
    items = "".join(
        f"<li><strong>{_esc(f['title'])}</strong> — {_esc(f['remediation'][0])} "
        f"<span class='mono ref'>{_esc(f['id'])}</span></li>"
        for f in picks
    )
    horizon = "within days" if any(SEV_ORDER[f["severity"]] <= 1 for f in picks) else "within the month"
    return f"""<section>
      <h2>Remediation Priority</h2>
      <p class="fine">Addressed in this order, starting {horizon}, the surface
      improves measurably:</p>
      <ol class="roadmap">{items}</ol>
    </section>"""


def _passed_section(record):
    checks = passed_checks(record)
    if not checks:
        return ""
    items = "".join(f"<li>{_esc(c)}</li>" for c in checks)
    return f"""<section>
      <h2>Checks That Passed</h2>
      <ul class="pass">{items}</ul>
    </section>"""


def _credential_section(record):
    cc = record.get("credential_checks")
    if cc is None:
        note = "Not performed for this scan."
    else:
        rows = []
        for f in cc.get("http_login_findings") or []:
            label = {
                "none_observed": "No rate limiting observed",
                "throttled": "Throttling in place",
                "lockout": "Lockout protection",
                "captcha": "CAPTCHA protection",
            }.get(f.get("verdict"), f.get("verdict"))
            color = "#B91C1C" if f.get("verdict") == "none_observed" else "#15803D"
            rows.append(
                f"<tr><td>{_esc(f.get('url'))}</td>"
                f"<td><span class='risk' style='background:{color}14;color:{color};'>{_esc(label)}</span></td>"
                f"<td>{_esc(f.get('detail'))}</td></tr>"
            )
        for d in cc.get("db_findings") or []:
            color = "#B91C1C" if d.get("vulnerable") else "#15803D"
            label = "Vulnerable" if d.get("vulnerable") else "No issue found"
            rows.append(
                f"<tr><td>Port {_esc(d.get('port'))}</td>"
                f"<td><span class='risk' style='background:{color}14;color:{color};'>{_esc(label)}</span></td>"
                f"<td>{_esc(d.get('check'))}: {_esc(d.get('detail'))}</td></tr>"
            )
        if rows:
            note = ("<table><thead><tr><th>Endpoint</th><th>Verdict</th><th>Detail</th></tr></thead>"
                    "<tbody>" + "".join(rows) + "</tbody></table>")
        else:
            note = ("Checks ran but no login endpoints or credential-protected "
                    "services presented themselves.")
        if cc.get("error"):
            note += f"<p class='empty'>Partial failure: {_esc(cc['error'])}</p>"
    return f"""<section>
      <h2>Credential &amp; Lockout Checks</h2>
      {note}
    </section>"""


def _ports_appendix(record):
    open_ports = [
        p for p in record.get("ports", [])
        if p.get("state") == "open"
    ]
    open_ports.sort(key=lambda p: (RISK_ORDER.get(p.get("risk"), 3), p.get("port", 0)))
    if open_ports:
        port_rows = "".join(
            f"""
            <tr>
              <td class="mono">{_esc(p['port'])}</td>
              <td><span class="risk risk-{_esc(p['risk'])}">{_esc(p['risk'])}</span></td>
              <td>{_esc(p['service'])}</td>
              <td>{_esc(p['version'])}</td>
            </tr>"""
            for p in open_ports
        )
    else:
        port_rows = '<tr><td colspan="4" class="empty">No open ports detected.</td></tr>'
    return f"""<section>
      <h2>Appendix A — Surface Manifest</h2>
      <table>
        <thead><tr><th>Port</th><th>Risk</th><th>Service</th><th>Version</th></tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </section>"""


def _score_appendix(record):
    risk = record.get("risk") or {}
    breakdown = risk.get("breakdown") or []
    score = risk.get("score")
    if not breakdown or score is None:
        return ""
    rows = "".join(
        f"<tr><td>{_esc(b['reason'])}</td><td class='mono neg'>{_esc(b['points'])}</td></tr>"
        for b in breakdown
    )
    return f"""<section>
      <h2>Appendix B — Score Derivation</h2>
      <table>
        <thead><tr><th>Finding</th><th>Points</th></tr></thead>
        <tbody>{rows}
        <tr class="total"><td>Final score</td><td class="mono">{_esc(score)}</td></tr></tbody>
      </table>
    </section>"""


def build_report_html(record):
    risk = record.get("risk") or {}
    score = risk.get("score")
    grade = risk.get("grade")
    compliance = record.get("compliance") or []

    findings = build_findings(record)

    grade_block = ""
    if score is not None and grade:
        color = _grade_color(grade)
        grade_block = f"""
        <div class="grade-box" style="border-color:{color};">
          <div class="grade-letter" style="color:{color};">{_esc(grade)}</div>
          <div class="grade-score">{_esc(score)}/100 overall</div>
        </div>"""

    compliance_html = ""
    if compliance:
        items = "".join(
            f"""
            <li>
              <strong>{_esc(t['category'])} — {_esc(t['name'])}</strong>
              <ul>{''.join(f'<li>{_esc(e)}</li>' for e in t['evidence'])}</ul>
            </li>"""
            for t in compliance
        )
        compliance_html = f"""
        <section>
          <h2>Framework Mapping — OWASP Top 10 (2021)</h2>
          <ul class="compliance">{items}</ul>
        </section>"""

    try:
        generated = datetime.utcnow().strftime("%d %B %Y")
    except Exception:
        generated = ""

    report_ref = f"PW-{record.get('id', '000'):0>4}-{datetime.now().year}"

    # section order chosen so a client can stop reading after the roadmap
    # and still have everything they need to act
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Security Assessment — {_esc(record.get('target'))}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  @page {{ size: A4; margin: 16mm; }}
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #EEF1F5; color: #101826; line-height: 1.6;
    padding: 32px 16px;
  }}
  .page {{ max-width: 820px; margin: 0 auto; background: #FFFFFF;
           border: 1px solid #DDE3EC; border-radius: 10px; padding: 44px 52px; }}

  .coverline {{ display: flex; justify-content: space-between; align-items: center;
                font-family: Consolas, monospace; font-size: 11px; letter-spacing: 0.14em;
                text-transform: uppercase; color: #64748B;
                border-bottom: 1px solid #E2E8F0; padding-bottom: 10px; margin-bottom: 24px; }}
  .coverline .classification {{ background: #B91C1C; color: #fff; padding: 2px 10px;
                                border-radius: 3px; letter-spacing: 0.18em; }}

  header {{ display: flex; justify-content: space-between; align-items: flex-start;
            border-bottom: 3px solid #101826; padding-bottom: 20px; margin-bottom: 30px;
            gap: 24px; flex-wrap: wrap; }}
  .brand {{ font-family: Consolas, monospace; font-weight: 700; font-size: 19px; }}
  .brand span {{ color: #0369A1; }}
  h1 {{ font-size: 23px; margin-top: 12px; line-height: 1.25; }}
  .meta {{ color: #64748B; font-size: 13px; margin-top: 6px; }}

  .grade-box {{ border: 2px solid; border-radius: 8px; padding: 12px 24px; text-align: center; }}
  .grade-letter {{ font-size: 42px; font-weight: 800; line-height: 1.05; }}
  .grade-score {{ font-size: 12px; color: #64748B; }}

  h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.12em;
        color: #334155; margin: 34px 0 12px; padding-bottom: 6px;
        border-bottom: 1px solid #E2E8F0; }}
  h3 {{ font-size: 13px; margin: 14px 0 5px; color: #101826; }}

  section {{ break-inside: avoid-page; }}
  .finding-card {{ border: 1px solid #E2E8F0; border-left: 4px solid #CBD5E1;
                   border-radius: 8px; padding: 18px 22px; margin-bottom: 20px;
                   break-inside: avoid-page; }}
  .finding-card header {{ display: flex; align-items: center; gap: 10px;
                          border-bottom: none; margin-bottom: 8px; padding-bottom: 0; flex-wrap: wrap; }}
  .finding-card p {{ font-size: 13.5px; }}
  .fid {{ color: #64748B; font-size: 12px; }}
  .ftitle {{ margin: 0 !important; font-size: 15px !important; }}
  .owasp {{ font-size: 11.5px; color: #64748B; margin: 4px 0 8px;
            font-family: Consolas, monospace; }}
  .sev {{ display: inline-block; border: 1.5px solid; border-radius: 4px;
          font-family: Consolas, monospace; font-size: 10.5px; font-weight: 700;
          padding: 1px 8px; letter-spacing: 0.08em; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; background: #F1F5F9; padding: 8px 12px;
        font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: #475569; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #EDF1F6; vertical-align: top; }}
  tr.total td {{ font-weight: 700; border-top: 2px solid #101826; border-bottom: none; }}
  table.kv th {{ width: 170px; background: transparent; text-transform: none;
                 font-size: 13px; letter-spacing: 0; color: #334155; }}
  .neg {{ color: #B91C1C; }}
  .empty {{ color: #64748B; font-style: italic; font-size: 13.5px; }}
  .fine {{ font-size: 12.5px; color: #475569; margin-top: 8px; }}
  .mono {{ font-family: Consolas, monospace; }}
  .ref {{ color: #94A3B8; font-size: 11px; }}

  ul.ev, ul.pass {{ margin: 6px 0 0 20px; font-size: 13px; color: #334155; }}
  ul.ev li, ul.pass li, ul.compliance ul li {{ margin-bottom: 4px; font-family: Consolas, monospace; font-size: 12.5px; }}
  ol.fix, ol.roadmap {{ margin: 6px 0 0 22px; font-size: 13.5px; }}
  ol.fix li, ol.roadmap li {{ margin-bottom: 7px; }}
  ol.roadmap li {{ margin-bottom: 11px; }}

  .risk {{ display: inline-block; padding: 1px 9px; border-radius: 99px;
           font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .risk-high {{ background: #FEE2E2; color: #B91C1C; }}
  .risk-medium {{ background: #FEF3C7; color: #B45309; }}
  .risk-low {{ background: #DCFCE7; color: #15803D; }}

  ul.compliance {{ list-style: none; }}
  ul.compliance > li {{ margin-bottom: 14px; font-size: 14px; }}
  ul.compliance ul {{ margin: 6px 0 0 20px; font-size: 13px; color: #334155; }}

  footer {{ margin-top: 38px; padding-top: 16px; border-top: 1px solid #E2E8F0;
            font-size: 11px; color: #94A3B8; line-height: 1.75; }}

  .toolbar {{ max-width: 820px; margin: 0 auto 16px; text-align: right; }}
  .toolbar button {{ background: #0369A1; color: #fff; border: none; border-radius: 6px;
                     padding: 9px 22px; font-size: 14px; font-weight: 600; cursor: pointer; }}
  .toolbar button:hover {{ background: #075985; }}

  @media print {{
    body {{ background: #FFFFFF; padding: 0; }}
    .page {{ border: none; border-radius: 0; padding: 0; max-width: none; }}
    .toolbar {{ display: none; }}
    h2 {{ break-after: avoid-page; }}
  }}
</style>
</head>
<body>
  <div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
  <div class="page">
    <div class="coverline">
      <span>Report {_esc(report_ref)}</span>
      <span class="classification">Commercial in confidence</span>
      <span>Generated {_esc(generated)}</span>
    </div>

    <header>
      <div>
        <div class="brand">Port<span>Watch</span></div>
        <div class="meta">automated external surface assessment</div>
        <h1>Security Assessment Report<br/>{_esc(record.get('target'))}</h1>
        <p class="meta">
          Assessed {_esc(_fmt_ts(record.get('timestamp')))}
          &nbsp;·&nbsp; Profile: {_esc((record.get('profile') or 'standard').title())}
        </p>
      </div>
      {grade_block}
    </header>

    <section>
      <h2>Executive Summary</h2>
      {_exec_summary(record, findings)}
    </section>

    {_scope_section(record)}

    {_findings_summary_table(findings)}

    {_findings_detail(findings)}

    {_roadmap(findings)}

    {_passed_section(record)}

    {compliance_html}

    {_credential_section(record)}

    {_ports_appendix(record)}

    {_score_appendix(record)}

    <section>
      <h2>Limitations &amp; Next Steps</h2>
      <p>This assessment was automated, external and non-invasive. It did not include
      authenticated testing, business-logic review, social engineering, or full-range
      port coverage. Absence of a finding is therefore not proof of absence of risk.</p>
      <p>Recommended cadence: re-assess after every material infrastructure or
      application change, and at minimum monthly. PortWatch's comparison view can
      diff consecutive scans of the same target to isolate exactly what moved.</p>
    </section>

    <footer>
      Generated by PortWatch · report {_esc(report_ref)} · classification:
      commercial in confidence — distribute only to stakeholders of
      {_esc(record.get('target'))}. Only scan systems you own or have explicit written
      permission to test.
    </footer>
  </div>
</body>
</html>"""
