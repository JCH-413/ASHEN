"""
report_builder.py
Builds HTML and CSV reports from scan, vulnerability, and exploit data.
"""
import csv
import io
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.exploit import Exploit


def build_report_data(db: Session, scan_id: int) -> dict:
    """Aggregate all data for a scan into a structured dict."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return {}

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    exploits = db.query(Exploit).filter(Exploit.scan_id == scan_id).all()

    target_ip = scan.target.ip_address if scan.target else "Unknown"
    user_email = scan.user.email if scan.user else "Unknown"

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in vulns:
        key = v.severity.lower() if v.severity else "unknown"
        sev_counts[key] = sev_counts.get(key, 0) + 1

    return {
        "scan_id": scan_id,
        "target_ip": target_ip,
        "user": user_email,
        "status": scan.status,
        "start_time": scan.start_time,
        "end_time": scan.end_time,
        "vulnerabilities": vulns,
        "exploits": exploits,
        "severity_counts": sev_counts,
    }


def generate_html_report(data: dict) -> str:
    """Render an HTML report from aggregated data."""
    if not data:
        return "<html><body><h1>No data available</h1></body></html>"

    vulns = data["vulnerabilities"]
    exploits = data["exploits"]
    sev = data["severity_counts"]

    vuln_rows = ""
    for v in vulns:
        vuln_rows += f"""
        <tr>
            <td>{v.port}</td>
            <td>{v.script_id}</td>
            <td class="sev-{v.severity.lower() if v.severity else 'unknown'}">{v.severity}</td>
            <td>{v.description or 'N/A'}</td>
        </tr>"""

    exploit_rows = ""
    for e in exploits:
        exploit_rows += f"""
        <tr>
            <td>{e.exploit_type}</td>
            <td>{e.tool_used}</td>
            <td>{e.target_ip}</td>
            <td>{e.status}</td>
            <td>{'Yes' if e.vulnerable else 'No' if e.vulnerable is not None else 'N/A'}</td>
            <td>{e.result_summary or 'N/A'}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ASHEN Security Report - Scan {data['scan_id']}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; color: #1a1a2e; }}
    h1 {{ color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: 10px; }}
    h2 {{ color: #0f3460; margin-top: 30px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }}
    th {{ background: #0f3460; color: white; }}
    tr:nth-child(even) {{ background: #f8f9fa; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
    .summary-card {{ background: #f8f9fa; border: 1px solid #ddd; border-radius: 8px; padding: 15px; text-align: center; }}
    .summary-card .value {{ font-size: 28px; font-weight: bold; }}
    .sev-critical {{ color: #dc3545; font-weight: bold; }}
    .sev-high {{ color: #fd7e14; font-weight: bold; }}
    .sev-medium {{ color: #ffc107; font-weight: bold; }}
    .sev-low {{ color: #28a745; }}
    .meta {{ color: #666; font-size: 13px; }}
    .footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #ddd; font-size: 12px; color: #999; }}
</style>
</head>
<body>
    <h1>ASHEN Security Assessment Report</h1>
    <p class="meta">
        <strong>Scan ID:</strong> {data['scan_id']} |
        <strong>Target:</strong> {data['target_ip']} |
        <strong>Analyst:</strong> {data['user']} |
        <strong>Status:</strong> {data['status']} |
        <strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
    </p>

    <h2>1. Executive Summary</h2>
    <div class="summary-grid">
        <div class="summary-card">
            <div class="value" style="color:#dc3545">{sev['critical']}</div>
            <div>Critical</div>
        </div>
        <div class="summary-card">
            <div class="value" style="color:#fd7e14">{sev['high']}</div>
            <div>High</div>
        </div>
        <div class="summary-card">
            <div class="value" style="color:#ffc107">{sev['medium']}</div>
            <div>Medium</div>
        </div>
        <div class="summary-card">
            <div class="value" style="color:#28a745">{sev['low']}</div>
            <div>Low</div>
        </div>
    </div>
    <p>Total vulnerabilities found: <strong>{len(vulns)}</strong> | Exploits executed: <strong>{len(exploits)}</strong></p>

    <h2>2. Vulnerability Details</h2>
    {'<table><thead><tr><th>Port</th><th>Script ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>' if vulns else '<p>No vulnerabilities detected.</p>'}

    <h2>3. Exploit Validation Results</h2>
    {'<table><thead><tr><th>Type</th><th>Tool</th><th>Target</th><th>Status</th><th>Vulnerable</th><th>Summary</th></tr></thead><tbody>' + exploit_rows + '</tbody></table>' if exploits else '<p>No exploits executed.</p>'}

    <h2>4. Recommendations</h2>
    <p>Review all critical and high-severity findings above. Prioritize patching and configuration hardening for confirmed vulnerabilities. Use the AI remediation module for detailed guidance per finding.</p>

    <div class="footer">
        Generated by ASHEN (Automated Security &amp; Host Exploitation Navigator) | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
    </div>
</body>
</html>"""


def generate_csv_report(data: dict) -> str:
    """Render a CSV report from aggregated data."""
    if not data:
        return ""

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ASHEN Security Report"])
    writer.writerow(["Scan ID", data["scan_id"]])
    writer.writerow(["Target", data["target_ip"]])
    writer.writerow(["Analyst", data["user"]])
    writer.writerow(["Status", data["status"]])
    writer.writerow([])

    writer.writerow(["--- Vulnerabilities ---"])
    writer.writerow(["Port", "Script ID", "Severity", "Description"])
    for v in data["vulnerabilities"]:
        writer.writerow([v.port, v.script_id, v.severity, v.description or "N/A"])

    writer.writerow([])
    writer.writerow(["--- Exploits ---"])
    writer.writerow(["Type", "Tool", "Target", "Status", "Vulnerable", "Summary"])
    for e in data["exploits"]:
        writer.writerow([
            e.exploit_type, e.tool_used, e.target_ip,
            e.status, e.vulnerable, e.result_summary or "N/A"
        ])

    return output.getvalue()
