"""
Remediation tracking service for PortWatch Pro.

Converts scan findings into trackable items with lifecycle:
  open -> in_progress -> remediated -> verified (by re-scan)
  open -> accepted_risk (with justification)
  open -> false_positive (with evidence)

Auto-populates findings from scan results and CVE intel.
Re-verification: when a new scan completes, check if previously-open
findings are still present and update status accordingly.
"""

from models.db import db, Finding, Scan, Project
from core.config import utcnow


def auto_create_findings(scan):
    """Extract findings from a completed scan and create Finding records.
    Idempotent: skips findings that already exist for this scan."""
    full = scan.get_full()
    existing = Finding.query.filter_by(scan_id=scan.id).count()
    if existing > 0:
        return []

    findings = []

    # Port-level findings
    for port in full.get("ports", []):
        if port.get("state") != "open":
            continue
        if port.get("risk") == "high":
            findings.append(_build_finding(
                scan, f"High-risk service exposed on port {port['port']}",
                f"Service '{port.get('service', 'unknown')}' ({port.get('version', '')}) is exposed on port {port['port']}. "
                f"This service should not be accessible from untrusted networks.",
                severity="high", port=port["port"], service=port.get("service"),
                remediation="Restrict access via firewall rules. If the service is not needed externally, bind it to localhost only.",
            ))

        # Script-based findings
        for script_name, output in port.get("scripts", {}).items():
            if not isinstance(output, str):
                continue
            if script_name.startswith("http-vuln-") and "VULNERABLE" in output.upper():
                findings.append(_build_finding(
                    scan, f"Vulnerability confirmed: {script_name} on port {port['port']}",
                    output[:500], severity="critical", port=port["port"],
                    service=port.get("service"),
                    remediation="Apply the vendor patch immediately. See CVE details for specific version requirements.",
                ))
            if script_name == "ssl-enum-ciphers" and any(w in output.lower() for w in ("weak", "rc4", "3des")):
                findings.append(_build_finding(
                    scan, f"Weak TLS ciphers on port {port['port']}",
                    f"Weak or deprecated cipher suites detected: {output[:300]}",
                    severity="medium", port=port["port"], service=port.get("service"),
                    remediation="Disable SSLv3, TLS 1.0, TLS 1.1. Remove RC4, 3DES, and export ciphers from the server configuration.",
                ))
            if script_name == "http-security-headers" and "missing" in output.lower():
                findings.append(_build_finding(
                    scan, f"Missing security headers on port {port['port']}",
                    output[:300], severity="low", port=port["port"],
                    service=port.get("service"),
                    remediation="Add Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options headers.",
                ))

    # CVE findings
    for finding in full.get("findings", []):
        cves = ",".join(finding.get("cve", []))
        findings.append(_build_finding(
            scan, finding.get("title", "CVE finding"),
            finding.get("evidence", ""), severity=finding.get("severity", "medium"),
            port=finding.get("port"), service=finding.get("service"),
            cve_ids=cves, cvss_score=finding.get("cvss"),
            remediation=finding.get("remediation", ""),
        ))

    # Credential findings
    cc = full.get("credential_checks") or {}
    for f in cc.get("http_login_findings", []):
        if f.get("verdict") == "none_observed":
            findings.append(_build_finding(
                scan, f"No rate limiting on login endpoint",
                f"URL: {f.get('url')}. {f.get('detail', '')}",
                severity="high", remediation="Implement rate limiting, account lockout, or CAPTCHA on login endpoints.",
            ))
    for d in cc.get("db_findings", []):
        if d.get("vulnerable"):
            findings.append(_build_finding(
                scan, f"Database authentication failure on port {d.get('port')}",
                d.get("detail", ""), severity="critical", port=d.get("port"),
                remediation="Set strong passwords for all database accounts. Disable default and empty-password accounts.",
            ))

    for f in findings:
        db.session.add(f)
    db.session.commit()
    return findings


def _build_finding(scan, title, description, severity="medium", port=None,
                   service=None, cve_ids="", cvss_score=None, remediation=""):
    return Finding(
        project_id=scan.project_id,
        scan_id=scan.id,
        title=title,
        description=description,
        severity=severity,
        port=port,
        service=service,
        cve_ids=cve_ids,
        cvss_score=cvss_score,
        remediation=remediation,
        status="open",
    )


def update_finding_status(finding_id, status, note="", user=None):
    """Update a finding's status with a note."""
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return None
    finding.status = status
    finding.status_note = note
    finding.updated_at = utcnow()
    db.session.commit()
    return finding


def verify_remediation(project_id, new_scan_id):
    """Compare open findings against a new scan. Mark as verified if the
    vulnerability is no longer present."""
    open_findings = Finding.query.filter_by(
        project_id=project_id, status="remediated"
    ).all()

    new_scan = db.session.get(Scan, new_scan_id)
    if not new_scan or new_scan.status != "completed":
        return []

    full = new_scan.get_full()
    open_ports = {p["port"] for p in full.get("ports", []) if p.get("state") == "open"}
    vuln_scripts = set()
    for p in full.get("ports", []):
        for name, out in p.get("scripts", {}).items():
            if isinstance(out, str) and "VULNERABLE" in out.upper():
                vuln_scripts.add(f"{p['port']}:{name}")

    verified = []
    for finding in open_findings:
        still_present = False
        if finding.port and finding.port in open_ports:
            # Check if the specific vulnerability is still there
            for p in full.get("ports", []):
                if p["port"] == finding.port:
                    for name, out in p.get("scripts", {}).items():
                        if isinstance(out, str) and name in (finding.title or ""):
                            still_present = True
        if not still_present:
            finding.status = "verified"
            finding.verified_scan_id = new_scan_id
            finding.status_note = f"Verified remediated by scan #{new_scan_id}"
            finding.updated_at = utcnow()
            verified.append(finding)

    db.session.commit()
    return verified


def get_project_findings_summary(project_id):
    """Summary counts by status and severity."""
    findings = Finding.query.filter_by(project_id=project_id).all()
    by_status = {}
    by_severity = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "by_status": by_status,
        "by_severity": by_severity,
        "open_critical": len([f for f in findings if f.status == "open" and f.severity == "critical"]),
        "open_high": len([f for f in findings if f.status == "open" and f.severity == "high"]),
    }
