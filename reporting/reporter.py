from rich.console import Console
from rich.table import Table
import json
import sys
import io
import os
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import base64

try:
    from xhtml2pdf import pisa
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

# Resolve the logo path relative to this file's location
_LOGO_PATH = str(Path(__file__).resolve().parent.parent / "screenshots" / "logo_diogenes.png")

class Reporter:
    CONFIDENCE_LABELS = {
        0.3: "Low",
        0.6: "Medium",
        0.9: "High"
    }
    
    RISK_LEVELS = {
        "xss": {"risk": "High", "cweid": "79", "color": "#d32f2f"},
        "sqli": {"risk": "Critical", "cweid": "89", "color": "#b71c1c"},
        "csrf": {"risk": "Medium", "cweid": "352", "color": "#f57c00"},
        "ssrf": {"risk": "High", "cweid": "918", "color": "#d32f2f"},
        "idor": {"risk": "High", "cweid": "639", "color": "#d32f2f"},
        "xxe": {"risk": "Critical", "cweid": "611", "color": "#b71c1c"},
        "reflection": {"risk": "Medium", "cweid": "200", "color": "#f57c00"},
        "state_change": {"risk": "Medium", "cweid": "352", "color": "#f57c00"}
    }
    
    REMEDIATION = {
        "xss": [
            "Implement output encoding based on context (HTML, JavaScript, CSS, URL)",
            "Use Content Security Policy (CSP) headers",
            "Sanitize user inputs using established libraries",
            "Use auto-escaping template engines"
        ],
        "sqli": [
            "Use parameterized queries or prepared statements",
            "Implement input validation and type checking",
            "Use ORM frameworks with built-in protection",
            "Apply principle of least privilege to database users"
        ],
        "csrf": [
            "Implement CSRF tokens (SameSite cookie attribute)",
            "Use double-submit cookie pattern",
            "Verify origin and referer headers",
            "Implement SameSite=Strict for sensitive operations"
        ],
        "ssrf": [
            "Validate and whitelist allowed URLs/domains",
            "Block access to internal IP ranges (10.0.0.0/8, 192.168.0.0/16, etc.)",
            "Disable unused URL schemes",
            "Use network segmentation for sensitive resources"
        ],
        "idor": [
            "Implement proper authorization checks for all resources",
            "Use indirect references instead of sequential IDs",
            "Validate user ownership of requested resources",
            "Implement access control matrices"
        ],
        "xxe": [
            "Disable XML external entity processing in parser",
            "Use defusedxml library instead of xml/lxml",
            "Validate and sanitize all XML input",
            "Use JSON instead of XML where possible"
        ],
        "reflection": [
            "Properly encode and escape all user-controlled output",
            "Use security headers (X-Content-Type-Options, X-Frame-Options)",
            "Implement input validation",
            "Use HttpOnly and Secure flags on cookies"
        ],
        "state_change": [
            "Protect state-changing operations with CSRF tokens",
            "Use appropriate HTTP methods (POST/PUT/DELETE for mutations)",
            "Require re-authentication for sensitive operations",
            "Implement rate limiting on critical operations"
        ]
    }
    
    def render(self, findings):
        if not findings:
            console = Console()
            console.print("[yellow]No observable security signals detected.[/yellow]")
            console.print("[dim]This does not guarantee absence of vulnerabilities.[/dim]")
            return
        
        table = Table(title="DIOGENES Security Report")
        
        table.add_column("Type", style="cyan")
        table.add_column("Endpoint", style="magenta")
        table.add_column("Details", style="white")
        table.add_column("Confidence", style="green")
        
        for f in findings:
            f_dict = f if isinstance(f, dict) else f.to_dict()
            
            # Determine confidence label
            confidence = f_dict.get("confidence", 0.5)
            if confidence >= 0.8:
                conf_label = "High (0.9)"
            elif confidence >= 0.6:
                conf_label = "Medium (0.6)"
            else:
                conf_label = "Low (0.3)"
            
            # Build evidence string
            evidence = f_dict.get("evidence", "")
            if f_dict.get("param"):
                evidence += f" (param={f_dict['param']})"

            payload = f_dict.get("payload")
            if payload:
                payload_str = str(payload)
                if len(payload_str) > 120:
                    payload_str = payload_str[:117] + "..."
                evidence += f" (payload={payload_str})"
            
            table.add_row(
                f_dict["type"].upper(),
                f_dict.get("endpoint", "-"),
                evidence,
                conf_label
            )
        
        console = Console(force_terminal=True, legacy_windows=True)
        console.print(table)
    
    def render_json(self, findings):
        """Return findings as JSON structure (SARIF-compatible)."""
        return {
            "tool": "DIOGENES",
            "findings": [
                f if isinstance(f, dict) else f.to_dict() 
                for f in findings
            ]
        }
    
    def render_html(self, findings, output_file="diogenes_report.html"):
        """Generate a comprehensive HTML report similar to OWASP ZAP."""
        if not findings:
            html_content = self._get_empty_report_html()
        else:
            html_content = self._generate_html_report(findings)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

    def render_pdf(self, findings, output_file="diogenes_report.pdf", target_url=""):
        """Generate a professional PDF report."""
        if not HAS_PDF:
            raise RuntimeError("PDF generation requires xhtml2pdf. Install it with: pip install xhtml2pdf")

        if not findings:
            html_content = self._get_empty_report_html_pdf(target_url)
        else:
            html_content = self._generate_pdf_html(findings, target_url)

        with open(output_file, 'wb') as pdf_file:
            status = pisa.CreatePDF(
                io.BytesIO(html_content.encode('utf-8')),
                dest=pdf_file,
            )

        if status.err:
            raise RuntimeError(f"PDF generation failed with {status.err} errors")

        return output_file

    def _generate_pdf_html(self, findings, target_url=""):
        """Generate a clean, professional PDF report with modern design."""
        findings_list = [f if isinstance(f, dict) else f.to_dict() for f in findings]
        stats = self._calculate_statistics(findings_list)
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        by_type = defaultdict(list)
        by_endpoint = defaultdict(list)
        for finding in findings_list:
            by_type[finding['type']].append(finding)
            by_endpoint[finding['endpoint']].append(finding)

        # Encode logo
        logo_data_uri = ""
        if os.path.exists(_LOGO_PATH):
            with open(_LOGO_PATH, 'rb') as lf:
                logo_b64 = base64.b64encode(lf.read()).decode()
            logo_data_uri = f"data:image/png;base64,{logo_b64}"

        # Risk gauge
        total = stats['total'] or 1
        risk_bars = []
        for label, count, color in [
            ("Critical", stats['critical'], "#c0392b"),
            ("High", stats['high'], "#e74c3c"),
            ("Medium", stats['medium'], "#e67e22"),
            ("Low", stats['low'], "#f39c12"),
        ]:
            if count > 0:
                pct = max(int((count / total) * 100), 2)
                risk_bars.append(f'<div style="background:{color};height:10px;width:{pct}%;display:inline-block;"></div>')
        risk_gauge = ''.join(risk_bars) if risk_bars else '<div style="background:#27ae60;height:10px;width:100%;"></div>'

        # Type distribution (clean horizontal bars)
        max_count = max(len(v) for v in by_type.values()) if by_type else 1
        type_rows = ''
        bar_colors = ['#3498db', '#9b59b6', '#e91e63', '#2ecc71', '#f39c12', '#16a085', '#e74c3c', '#34495e']
        for i, (vtype, vfindings) in enumerate(sorted(by_type.items())):
            pct = int((len(vfindings) / max_count) * 100) if max_count else 0
            pct = max(pct, 5)
            color = bar_colors[i % len(bar_colors)]
            risk_info = self.RISK_LEVELS.get(vtype, {'risk': 'Low', 'cweid': 'N/A'})
            type_rows += f'''<tr style="border-bottom:1px solid #ecf0f1;">
                <td style="width:90px;font-weight:700;text-transform:uppercase;font-size:9px;color:#2c3e50;padding:8px 10px;">{vtype}</td>
                <td style="padding:8px 10px;">
                    <div style="background:#f8f9fa;border-radius:4px;height:22px;width:100%;">
                        <div style="background:{color};border-radius:4px;height:22px;width:{pct}%;text-align:center;color:#fff;font-size:9px;font-weight:700;line-height:22px;">{len(vfindings)}</div>
                    </div>
                </td>
                <td style="width:70px;text-align:center;font-size:9px;font-weight:700;padding:8px 6px;color:{risk_info.get('color','#7f8c8d')};">{risk_info['risk'].upper()}</td>
            </tr>'''

        # Vulnerability summary table
        type_table = '<table cellspacing="0" cellpadding="0" style="width:100%;margin-bottom:0;border:1px solid #ecf0f1;">'
        type_table += '<thead><tr style="background:#34495e;"><th style="color:#fff;padding:10px 12px;text-align:left;font-size:9px;font-weight:700;border:none;text-transform:uppercase;">Type</th><th style="color:#fff;padding:10px 12px;text-align:center;font-size:9px;font-weight:700;border:none;text-transform:uppercase;width:70px;">Count</th><th style="color:#fff;padding:10px 12px;text-align:center;font-size:9px;font-weight:700;border:none;text-transform:uppercase;width:80px;">Risk Level</th><th style="color:#fff;padding:10px 12px;text-align:center;font-size:9px;font-weight:700;border:none;text-transform:uppercase;width:80px;">CWE ID</th></tr></thead><tbody>'
        for i, (vtype, vfindings) in enumerate(sorted(by_type.items())):
            risk_info = self.RISK_LEVELS.get(vtype, {'risk': 'Unknown', 'cweid': 'N/A', 'color': '#7f8c8d'})
            bg = '#f8f9fa' if i % 2 == 0 else '#fff'
            type_table += f'<tr style="background:{bg};"><td style="padding:10px 12px;font-weight:700;text-transform:uppercase;font-size:9px;border:none;">{vtype}</td><td style="padding:10px 12px;font-size:10px;text-align:center;font-weight:700;border:none;">{len(vfindings)}</td><td style="padding:10px 12px;font-size:9px;text-align:center;font-weight:700;color:{risk_info["color"]};border:none;">{risk_info["risk"]}</td><td style="padding:10px 12px;font-size:9px;text-align:center;border:none;color:#7f8c8d;">CWE-{risk_info["cweid"]}</td></tr>'
        type_table += '</tbody></table>'

        # Endpoint table
        endpoint_table = '<table cellspacing="0" cellpadding="0" style="width:100%;margin-bottom:0;border:1px solid #ecf0f1;">'
        endpoint_table += '<thead><tr style="background:#34495e;"><th style="color:#fff;padding:10px 12px;text-align:left;font-size:9px;font-weight:700;border:none;text-transform:uppercase;">Endpoint</th><th style="color:#fff;padding:10px 12px;text-align:center;font-size:9px;font-weight:700;border:none;text-transform:uppercase;width:70px;">Findings</th><th style="color:#fff;padding:10px 12px;text-align:left;font-size:9px;font-weight:700;border:none;text-transform:uppercase;">Types</th></tr></thead><tbody>'
        for i, (endpoint, efindings) in enumerate(sorted(by_endpoint.items(), key=lambda x: -len(x[1]))):
            types_str = ', '.join(sorted(set(f['type'].upper() for f in efindings)))
            bg = '#f8f9fa' if i % 2 == 0 else '#fff'
            endpoint_table += f'<tr style="background:{bg};"><td style="padding:8px 12px;font-family:monospace;font-size:8px;border:none;word-break:break-all;">{endpoint}</td><td style="padding:8px 12px;text-align:center;font-size:10px;font-weight:700;border:none;">{len(efindings)}</td><td style="padding:8px 12px;font-size:8px;border:none;">{types_str}</td></tr>'
        endpoint_table += '</tbody></table>'

        # Detailed findings (clean card design)
        detailed_html = ''
        for idx, finding in enumerate(findings_list, 1):
            vuln_type = finding['type']
            risk_info = self.RISK_LEVELS.get(vuln_type, {'risk': 'Low', 'color': '#f39c12'})
            risk = risk_info['risk']
            confidence = finding.get('confidence', 0.5)
            accent_color = risk_info['color']

            # Details table
            rows = f'''<tr><td style="font-weight:700;color:#7f8c8d;width:100px;padding:6px 10px;font-size:9px;vertical-align:top;border-bottom:1px solid #f8f9fa;text-transform:uppercase;">Endpoint</td><td style="font-family:monospace;font-size:8px;padding:6px 10px;border-bottom:1px solid #f8f9fa;word-break:break-all;color:#2c3e50;">{finding.get('endpoint', 'N/A')}</td></tr>
            <tr><td style="font-weight:700;color:#7f8c8d;width:100px;padding:6px 10px;font-size:9px;vertical-align:top;border-bottom:1px solid #f8f9fa;text-transform:uppercase;">Evidence</td><td style="font-size:9px;padding:6px 10px;border-bottom:1px solid #f8f9fa;color:#2c3e50;">{finding.get('evidence', 'No evidence provided')}</td></tr>'''
            if finding.get('param'):
                rows += f'<tr><td style="font-weight:700;color:#7f8c8d;width:100px;padding:6px 10px;font-size:9px;border-bottom:1px solid #f8f9fa;text-transform:uppercase;">Parameter</td><td style="font-family:monospace;font-size:8px;padding:6px 10px;border-bottom:1px solid #f8f9fa;color:#2c3e50;">{finding["param"]}</td></tr>'
            if finding.get('payload'):
                payload_str = str(finding['payload'])
                if len(payload_str) > 170:
                    payload_str = payload_str[:167] + '...'
                rows += f'<tr><td style="font-weight:700;color:#7f8c8d;width:100px;padding:6px 10px;font-size:9px;vertical-align:top;border-bottom:1px solid #f8f9fa;text-transform:uppercase;">Payload</td><td style="font-family:monospace;font-size:7px;padding:6px 10px;background:#f8f9fa;border-bottom:1px solid #ecf0f1;word-break:break-all;color:#34495e;">{payload_str}</td></tr>'
            if finding.get('status_code'):
                rows += f'<tr><td style="font-weight:700;color:#7f8c8d;width:100px;padding:6px 10px;font-size:9px;border-bottom:1px solid #f8f9fa;text-transform:uppercase;">Status Code</td><td style="font-size:9px;padding:6px 10px;border-bottom:1px solid #f8f9fa;color:#2c3e50;">{finding["status_code"]}</td></tr>'

            # Remediation
            remediation_html = ''
            remediation_items = self.REMEDIATION.get(vuln_type, [])
            if remediation_items:
                items = ''.join(f'<li style="margin-bottom:4px;font-size:8px;color:#2c3e50;line-height:1.4;">{item}</li>' for item in remediation_items)
                remediation_html = f'''<div style="background:#ecf9f2;border-left:3px solid #27ae60;padding:10px 12px;margin-top:10px;">
                    <strong style="color:#27ae60;font-size:9px;text-transform:uppercase;letter-spacing:0.5px;">Recommended Remediation</strong>
                    <ul style="margin:6px 0 0 14px;padding:0;">{items}</ul>
                </div>'''

            detailed_html += f'''<div style="border:1px solid #ecf0f1;border-left:4px solid {accent_color};background:#fff;padding:14px 16px;margin-bottom:14px;page-break-inside:avoid;">
                <table cellspacing="0" cellpadding="0" style="width:100%;border:none;margin:0 0 10px 0;"><tr>
                    <td style="border:none;padding:0;">
                        <span style="font-size:11px;font-weight:800;text-transform:uppercase;color:#2c3e50;letter-spacing:0.5px;">{vuln_type}</span>
                        <span style="background:{accent_color};color:#fff;padding:3px 10px;font-size:7px;font-weight:800;margin-left:10px;text-transform:uppercase;letter-spacing:0.8px;">{risk}</span>
                        <span style="background:#ecf0f1;color:#34495e;padding:3px 8px;font-size:7px;font-weight:700;margin-left:6px;text-transform:uppercase;">Conf: {confidence:.0%}</span>
                    </td>
                    <td style="border:none;text-align:right;color:#bdc3c7;font-size:9px;font-weight:700;padding:0;">#{idx}</td>
                </tr></table>
                <table cellspacing="0" cellpadding="0" style="width:100%;border:1px solid #ecf0f1;margin:0;">{rows}</table>
                {remediation_html}
            </div>'''

        # Logo
        logo_img = f'<img src="{logo_data_uri}" width="60" height="60" style="border-radius:4px;" />' if logo_data_uri else ''

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DIOGENES Security Report · {target_url}</title>
    <style>
        @page {{ size: A4; margin: 2.2cm 2cm; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 10px; color: #2c3e50; line-height: 1.6; }}
        h1 {{ font-size: 28px; font-weight: 800; margin: 0; color: #fff; letter-spacing: -0.8px; }}
        h2 {{
            font-size: 12px;
            font-weight: 800;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 6px;
            margin: 24px 0 14px 0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
    </style>
</head>
<body>
    <!-- Header -->
    <div style="background:linear-gradient(135deg, #3498db 0%, #2980b9 100%);padding:28px 24px;margin-bottom:24px;border-radius:2px;">
        <table cellspacing="0" cellpadding="0" style="width:100%;border:none;">
            <tr>
                <td style="border:none;vertical-align:middle;width:70px;padding:0;">{logo_img}</td>
                <td style="border:none;vertical-align:middle;padding-left:18px;">
                    <h1>DIOGENES</h1>
                    <div style="font-size:10px;opacity:0.9;margin-top:3px;letter-spacing:0.3px;">Web Application Security Assessment Report</div>
                </td>
            </tr>
        </table>
        <hr style="border:none;border-top:1px solid rgba(255,255,255,0.2);margin:18px 0;" />
        <table cellspacing="0" cellpadding="0" style="width:100%;border:none;">
            <tr>
                <td style="border:none;width:50%;padding:0;">
                    <div style="font-size:7px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,0.7);margin-bottom:4px;">Target Application</div>
                    <div style="font-size:11px;font-weight:700;color:#fff;">{target_url or 'N/A'}</div>
                </td>
                <td style="border:none;width:25%;padding:0;">
                    <div style="font-size:7px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,0.7);margin-bottom:4px;">Scan Date</div>
                    <div style="font-size:10px;font-weight:600;color:#fff;">{datetime.now().strftime('%Y-%m-%d')}</div>
                </td>
                <td style="border:none;width:25%;padding:0;">
                    <div style="font-size:7px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,0.7);margin-bottom:4px;">Scan Time</div>
                    <div style="font-size:10px;font-weight:600;color:#fff;">{datetime.now().strftime('%H:%M:%S')}</div>
                </td>
            </tr>
        </table>
    </div>

    <!-- Executive Summary -->
    <h2>Executive Summary</h2>
    <p style="font-size:9px;color:#7f8c8d;margin:0 0 14px 0;line-height:1.6;">
        This security assessment identified <strong style="color:#2c3e50;">{stats['total']}</strong> potential security findings
        across <strong style="color:#2c3e50;">{stats['endpoints']}</strong> endpoints. Findings are categorized by severity level and require validation.
    </p>

    <div style="margin-bottom:16px;">
        <div style="display:inline-block;width:15.5%;text-align:center;padding:12px 4px;margin:0 4px 0 0;background:#fff;border:2px solid #ecf0f1;vertical-align:top;">
            <div style="font-size:26px;font-weight:900;color:#3498db;">{stats['total']}</div>
            <div style="font-size:7px;text-transform:uppercase;letter-spacing:1px;color:#7f8c8d;margin-top:3px;font-weight:700;">Total</div>
        </div>
        <div style="display:inline-block;width:15.5%;text-align:center;padding:12px 4px;margin:0 4px 0 0;background:#fff;border:2px solid #ecf0f1;vertical-align:top;">
            <div style="font-size:26px;font-weight:900;color:#c0392b;">{stats['critical']}</div>
            <div style="font-size:7px;text-transform:uppercase;letter-spacing:1px;color:#7f8c8d;margin-top:3px;font-weight:700;">Critical</div>
        </div>
        <div style="display:inline-block;width:15.5%;text-align:center;padding:12px 4px;margin:0 4px 0 0;background:#fff;border:2px solid #ecf0f1;vertical-align:top;">
            <div style="font-size:26px;font-weight:900;color:#e74c3c;">{stats['high']}</div>
            <div style="font-size:7px;text-transform:uppercase;letter-spacing:1px;color:#7f8c8d;margin-top:3px;font-weight:700;">High</div>
        </div>
        <div style="display:inline-block;width:15.5%;text-align:center;padding:12px 4px;margin:0 4px 0 0;background:#fff;border:2px solid #ecf0f1;vertical-align:top;">
            <div style="font-size:26px;font-weight:900;color:#e67e22;">{stats['medium']}</div>
            <div style="font-size:7px;text-transform:uppercase;letter-spacing:1px;color:#7f8c8d;margin-top:3px;font-weight:700;">Medium</div>
        </div>
        <div style="display:inline-block;width:15.5%;text-align:center;padding:12px 4px;margin:0 4px 0 0;background:#fff;border:2px solid #ecf0f1;vertical-align:top;">
            <div style="font-size:26px;font-weight:900;color:#f39c12;">{stats['low']}</div>
            <div style="font-size:7px;text-transform:uppercase;letter-spacing:1px;color:#7f8c8d;margin-top:3px;font-weight:700;">Low</div>
        </div>
        <div style="display:inline-block;width:15.5%;text-align:center;padding:12px 4px;margin:0;background:#fff;border:2px solid #ecf0f1;vertical-align:top;">
            <div style="font-size:26px;font-weight:900;color:#2c3e50;">{stats['endpoints']}</div>
            <div style="font-size:7px;text-transform:uppercase;letter-spacing:1px;color:#7f8c8d;margin-top:3px;font-weight:700;">Endpoints</div>
        </div>
    </div>

    <!-- Risk Distribution -->
    <div style="background:#fff;border:1px solid #ecf0f1;height:10px;width:100%;margin:0 0 4px 0;">
        {risk_gauge}
    </div>
    <table cellspacing="0" cellpadding="0" style="width:100%;border:none;margin-bottom:18px;">
        <tr>
            <td style="border:none;font-size:7px;color:#c0392b;padding:0;font-weight:700;">■ CRITICAL</td>
            <td style="border:none;font-size:7px;color:#e74c3c;padding:0;font-weight:700;">■ HIGH</td>
            <td style="border:none;font-size:7px;color:#e67e22;padding:0;font-weight:700;">■ MEDIUM</td>
            <td style="border:none;font-size:7px;color:#f39c12;padding:0;font-weight:700;">■ LOW</td>
        </tr>
    </table>

    <!-- Findings Distribution -->
    <h2>Findings Distribution</h2>
    <table cellspacing="0" cellpadding="0" style="width:100%;border:1px solid #ecf0f1;margin-bottom:20px;">{type_rows}</table>

    <!-- Vulnerability Summary -->
    <h2>Vulnerability Summary</h2>
    {type_table}

    <pdf:nextpage />

    <!-- Affected Endpoints -->
    <h2>Affected Endpoints</h2>
    {endpoint_table}

    <!-- Detailed Findings -->
    <h2 style="margin-top:24px;">Detailed Findings</h2>
    {detailed_html}

    <!-- Footer -->
    <div style="text-align:center;font-size:7px;color:#bdc3c7;margin-top:28px;border-top:1px solid #ecf0f1;padding-top:10px;text-transform:uppercase;letter-spacing:0.8px;">
        DIOGENES Security Report · {target_url} · Generated {scan_time} · Confidential
    </div>
</body>
</html>"""
        return html

    def _get_empty_report_html_pdf(self, target_url=""):
        """Clean, professional empty-findings PDF."""
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        logo_data_uri = ""
        if os.path.exists(_LOGO_PATH):
            with open(_LOGO_PATH, 'rb') as lf:
                logo_b64 = base64.b64encode(lf.read()).decode()
            logo_data_uri = f"data:image/png;base64,{logo_b64}"
        logo_img = f'<img src="{logo_data_uri}" width="60" height="60" style="border-radius:4px;" />' if logo_data_uri else ''

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DIOGENES Security Report · {target_url}</title>
    <style>
        @page {{ size: A4; margin: 2.2cm 2cm; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 11px; color: #2c3e50; line-height: 1.6; }}
        h1 {{ font-size: 28px; font-weight: 800; margin: 0; color: #fff; letter-spacing: -0.8px; }}
    </style>
</head>
<body>
    <div style="background:linear-gradient(135deg, #3498db 0%, #2980b9 100%);padding:28px 24px;margin-bottom:24px;border-radius:2px;">
        <table cellspacing="0" cellpadding="0" style="width:100%;border:none;">
            <tr>
                <td style="border:none;vertical-align:middle;width:70px;padding:0;">{logo_img}</td>
                <td style="border:none;vertical-align:middle;padding-left:18px;">
                    <h1>DIOGENES</h1>
                    <div style="font-size:10px;opacity:0.9;margin-top:3px;letter-spacing:0.3px;">Web Application Security Assessment Report</div>
                </td>
            </tr>
        </table>
        <hr style="border:none;border-top:1px solid rgba(255,255,255,0.2);margin:18px 0;" />
        <table cellspacing="0" cellpadding="0" style="width:100%;border:none;">
            <tr>
                <td style="border:none;width:50%;padding:0;">
                    <div style="font-size:7px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,0.7);margin-bottom:4px;">Target Application</div>
                    <div style="font-size:11px;font-weight:700;color:#fff;">{target_url or 'N/A'}</div>
                </td>
                <td style="border:none;width:25%;padding:0;">
                    <div style="font-size:7px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,0.7);margin-bottom:4px;">Scan Date</div>
                    <div style="font-size:10px;font-weight:600;color:#fff;">{datetime.now().strftime('%Y-%m-%d')}</div>
                </td>
                <td style="border:none;width:25%;padding:0;">
                    <div style="font-size:7px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,0.7);margin-bottom:4px;">Scan Time</div>
                    <div style="font-size:10px;font-weight:600;color:#fff;">{datetime.now().strftime('%H:%M:%S')}</div>
                </td>
            </tr>
        </table>
    </div>
    <div style="background:#fff;border:2px solid #27ae60;padding:50px 30px;text-align:center;margin:50px 0;">
        <div style="font-size:48px;color:#27ae60;margin-bottom:12px;">✓</div>
        <h2 style="color:#27ae60;font-size:18px;font-weight:800;margin:0 0 12px 0;text-transform:uppercase;letter-spacing:0.5px;">No Security Findings</h2>
        <p style="color:#7f8c8d;font-size:10px;margin:0;">No observable security signals were detected during this automated scan.</p>
        <p style="color:#bdc3c7;font-size:8px;margin:10px 0 0 0;">This report does not guarantee the absence of vulnerabilities. Manual security validation is recommended.</p>
    </div>
    <div style="text-align:center;font-size:7px;color:#bdc3c7;margin-top:30px;border-top:1px solid #ecf0f1;padding-top:10px;text-transform:uppercase;letter-spacing:0.8px;">
        DIOGENES Security Report · {target_url} · Generated {scan_time} · Confidential
    </div>
</body>
</html>"""
    
    def _generate_html_report(self, findings):
        """Generate the complete HTML report."""
        # Prepare data
        findings_list = [f if isinstance(f, dict) else f.to_dict() for f in findings]
        
        # Calculate statistics
        stats = self._calculate_statistics(findings_list)
        
        # Group findings by type
        by_type = defaultdict(list)
        by_endpoint = defaultdict(list)
        
        for finding in findings_list:
            by_type[finding["type"]].append(finding)
            by_endpoint[finding["endpoint"]].append(finding)
        
        # Encode logo
        logo_data_uri = ""
        if os.path.exists(_LOGO_PATH):
            with open(_LOGO_PATH, 'rb') as lf:
                logo_b64 = base64.b64encode(lf.read()).decode()
            logo_data_uri = f"data:image/png;base64,{logo_b64}"
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DIOGENES Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #2c3e50;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }}
        
        .main-container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .report-card {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            margin-bottom: 30px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320"><path fill="rgba(255,255,255,0.05)" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,122.7C672,117,768,139,864,154.7C960,171,1056,181,1152,165.3C1248,149,1344,107,1392,85.3L1440,64L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path></svg>') bottom center no-repeat;
            background-size: cover;
            opacity: 0.3;
        }}
        
        .logo-container {{
            display: inline-block;
            width: 120px;
            height: 120px;
            background: white;
            border-radius: 50%;
            padding: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
            position: relative;
            z-index: 1;
        }}
        
        .logo-container img {{
            width: 100%;
            height: 100%;
            object-fit: contain;
            border-radius: 50%;
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: -1px;
            position: relative;
            z-index: 1;
            text-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.95;
            font-weight: 300;
            letter-spacing: 2px;
            text-transform: uppercase;
            position: relative;
            z-index: 1;
        }}
        
        .timestamp {{
            color: rgba(255,255,255,0.8);
            font-size: 0.9em;
            margin-top: 20px;
            position: relative;
            z-index: 1;
        }}
        
        .content-section {{
            padding: 40px;
        }}
        
        .section-header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        
        .section-header h2 {{
            font-size: 1.8em;
            color: #2c3e50;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .section-header p {{
            color: #7f8c8d;
            font-size: 1.05em;
        }}
        
        .summary-box {{
            background: linear-gradient(135deg, #f6f9fc 0%, #eef2f7 100%);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            border: 2px solid #e1e8ed;
        }}
        
        .summary-title {{
            font-size: 1.3em;
            color: #2c3e50;
            margin-bottom: 20px;
            font-weight: 700;
            text-align: center;
        }}
        
        .stats-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #d1d8e0;
        }}
        
        .stats-row:last-child {{
            border-bottom: none;
        }}
        
        .stat-label {{
            font-size: 1.1em;
            color: #546e7a;
            font-weight: 500;
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: 800;
            padding: 8px 20px;
            border-radius: 8px;
            min-width: 80px;
            text-align: center;
        }}
        
        .stat-value.total {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        .stat-value.critical {{
            background: linear-gradient(135deg, #c0392b 0%, #8e44ad 100%);
            color: white;
        }}
        
        .stat-value.high {{
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
        }}
        
        .stat-value.medium {{
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
            color: white;
        }}
        
        .stat-value.low {{
            background: linear-gradient(135deg, #f1c40f 0%, #f39c12 100%);
            color: white;
        }}
        
        .stat-value.endpoints {{
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
        }}
        
        .risk-distribution {{
            background: white;
            border-radius: 8px;
            height: 40px;
            overflow: hidden;
            margin: 20px 0;
            display: flex;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .risk-bar {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
            font-size: 0.9em;
            transition: all 0.3s ease;
        }}
        
        .risk-bar:hover {{
            opacity: 0.8;
        }}
        
        .risk-bar.critical {{
            background: #c0392b;
        }}
        
        .risk-bar.high {{
            background: #e74c3c;
        }}
        
        .risk-bar.medium {{
            background: #f39c12;
        }}
        
        .risk-bar.low {{
            background: #f1c40f;
        }}
        
        .chart-row {{
            display: flex;
            gap: 30px;
            margin: 30px 0;
        }}
        
        .chart-box {{
            flex: 1;
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
        }}
        
        .chart-box h3 {{
            margin-bottom: 20px;
            color: #2c3e50;
            font-size: 1.2em;
            text-align: center;
        }}
        
        .finding-card {{
            background: white;
            border-radius: 12px;
            border-left: 6px solid #667eea;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .finding-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.12);
        }}
        
        .finding-card.critical {{
            border-left-color: #c0392b;
        }}
        
        .finding-card.high {{
            border-left-color: #e74c3c;
        }}
        
        .finding-card.medium {{
            border-left-color: #f39c12;
        }}
        
        .finding-card.low {{
            border-left-color: #f1c40f;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #ecf0f1;
        }}
        
        .finding-type {{
            font-weight: 800;
            font-size: 1.3em;
            text-transform: uppercase;
            color: #2c3e50;
        }}
        
        .badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge.critical {{
            background: #c0392b;
            color: white;
        }}
        
        .badge.high {{
            background: #e74c3c;
            color: white;
        }}
        
        .badge.medium {{
            background: #f39c12;
            color: white;
        }}
        
        .badge.low {{
            background: #f1c40f;
            color: #2c3e50;
        }}
        
        .confidence {{
            display: inline-block;
            margin-left: 10px;
            padding: 6px 12px;
            background: #e3f2fd;
            color: #1565c0;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .finding-details {{
            margin-top: 15px;
        }}
        
        .detail-row {{
            margin-bottom: 12px;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .detail-label {{
            font-weight: 700;
            color: #546e7a;
            display: block;
            margin-bottom: 5px;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        
        .detail-value {{
            color: #2c3e50;
            word-break: break-word;
            font-size: 0.95em;
        }}
        
        .code-block {{
            background: #263238;
            color: #aed581;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 8px;
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.2);
        }}
        
        .remediation {{
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            border-left: 4px solid #28a745;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}
        
        .remediation h4 {{
            color: #155724;
            margin-bottom: 12px;
            font-size: 1.1em;
            font-weight: 700;
        }}
        
        .remediation ul {{
            margin-left: 20px;
            color: #2c3e50;
        }}
        
        .remediation li {{
            margin-bottom: 8px;
            line-height: 1.6;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            margin: 20px 0;
        }}
        
        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        th {{
            padding: 18px 15px;
            text-align: left;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.9em;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        tbody tr:last-child td {{
            border-bottom: none;
        }}
        
        .risk-critical {{
            color: #c0392b;
            font-weight: 700;
        }}
        
        .risk-high {{
            color: #e74c3c;
            font-weight: 700;
        }}
        
        .risk-medium {{
            color: #f39c12;
            font-weight: 700;
        }}
        
        .risk-low {{
            color: #f1c40f;
            font-weight: 700;
        }}
        
        .endpoint-tag {{
            background: #ecf0f1;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.9em;
            font-family: 'Monaco', 'Menlo', monospace;
            color: #2c3e50;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px 40px;
            background: #f8f9fa;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        .footer p {{
            margin: 5px 0;
        }}
        
        .divider {{
            height: 3px;
            background: linear-gradient(90deg, transparent, #667eea, #764ba2, #667eea, transparent);
            margin: 30px 0;
            border-radius: 3px;
        }}
        
        @media (max-width: 768px) {{
            .chart-row {{
                flex-direction: column;
            }}
            
            .stats-row {{
                flex-direction: column;
                text-align: center;
                gap: 10px;
            }}
            
            .finding-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="main-container">
        <div class="report-card">
            <div class="header">
                <div class="logo-container">
                    {f'<img src="{logo_data_uri}" alt="DIOGENES Logo" />' if logo_data_uri else '<div style="font-size: 50px;">🔮</div>'}
                </div>
                <h1>DIOGENES</h1>
                <p class="subtitle">Web Application Security Assessment Report</p>
                <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
            
            <div class="content-section">
                <div class="section-header">
                    <h2>Executive Summary</h2>
                    <p>Comprehensive security analysis and vulnerability assessment</p>
                </div>
                
                <div class="summary-box">
                    <div class="summary-title">Security Assessment Overview</div>
                    
                    <div class="stats-row">
                        <span class="stat-label">Total Findings Detected</span>
                        <span class="stat-value total">{stats['total']}</span>
                    </div>
                    
                    <div class="stats-row">
                        <span class="stat-label">Critical Risk Issues</span>
                        <span class="stat-value critical">{stats['critical']}</span>
                    </div>
                    
                    <div class="stats-row">
                        <span class="stat-label">High Risk Issues</span>
                        <span class="stat-value high">{stats['high']}</span>
                    </div>
                    
                    <div class="stats-row">
                        <span class="stat-label">Medium Risk Issues</span>
                        <span class="stat-value medium">{stats['medium']}</span>
                    </div>
                    
                    <div class="stats-row">
                        <span class="stat-label">Low Risk Issues</span>
                        <span class="stat-value low">{stats['low']}</span>
                    </div>
                    
                    <div class="stats-row">
                        <span class="stat-label">Affected Endpoints</span>
                        <span class="stat-value endpoints">{stats['endpoints']}</span>
                    </div>
                </div>
                
                {self._generate_risk_distribution_inline(stats)}
                
                <div class="divider"></div>
                
                <div class="chart-row">
                    <div class="chart-box">
                        <h3>Risk Level Distribution</h3>
                        <canvas id="riskChart"></canvas>
                    </div>
                    <div class="chart-box">
                        <h3>Vulnerability Types</h3>
                        <canvas id="typeChart"></canvas>
                    </div>
                </div>
                
                <div class="divider"></div>
                
                <div class="section-header">
                    <h2>Vulnerability Type Summary</h2>
                </div>
                
                {self._generate_type_summary(by_type)}
                
                <div class="divider"></div>
                
                <div class="section-header">
                    <h2>Affected Endpoints</h2>
                </div>
                
                {self._generate_endpoint_summary(by_endpoint)}
                
                <div class="divider"></div>
                
                <div class="section-header">
                    <h2>Detailed Security Findings</h2>
                    <p>Comprehensive analysis of identified vulnerabilities</p>
                </div>
                
                {self._generate_detailed_findings(findings_list)}
            </div>
            
            <div class="footer">
                <p><strong>DIOGENES</strong> - Searching for truth with a lamp, not a weapon.</p>
                <p>This report contains security observations that require manual verification.</p>
            </div>
        </div>
    </div>
    
    <script>
        // Risk Level Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{stats['critical']}, {stats['high']}, {stats['medium']}, {stats['low']}],
                    backgroundColor: ['#c0392b', '#e74c3c', '#f39c12', '#f1c40f'],
                    borderColor: '#fff',
                    borderWidth: 3
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 15,
                            font: {{
                                size: 12,
                                weight: 'bold'
                            }}
                        }}
                    }}
                }}
            }}
        }});
        
        // Type Chart
        const typeCtx = document.getElementById('typeChart').getContext('2d');
        const typeLabels = {json.dumps(list(by_type.keys()))};
        const typeValues = {json.dumps([len(by_type[t]) for t in by_type.keys()])};
        const colors = ['#667eea', '#764ba2', '#f093fb', '#4b7bec', '#5f27cd', '#00d2d3', '#ff6348', '#ff9ff3'];
        
        new Chart(typeCtx, {{
            type: 'bar',
            data: {{
                labels: typeLabels,
                datasets: [{{
                    label: 'Number of Findings',
                    data: typeValues,
                    backgroundColor: colors.slice(0, typeLabels.length),
                    borderRadius: 8,
                    borderSkipped: false
                }}]
            }},
            options: {{
                responsive: true,
                indexAxis: 'y',
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    x: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1,
                            font: {{
                                weight: 'bold'
                            }}
                        }},
                        grid: {{
                            color: '#ecf0f1'
                        }}
                    }},
                    y: {{
                        ticks: {{
                            font: {{
                                weight: 'bold'
                            }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_risk_distribution_inline(self, stats):
        """Generate inline risk distribution bar."""
        total = stats['total'] or 1
        critical_pct = (stats['critical'] / total) * 100
        high_pct = (stats['high'] / total) * 100
        medium_pct = (stats['medium'] / total) * 100
        low_pct = (stats['low'] / total) * 100
        
        html = '<div class="risk-distribution">'
        if stats['critical'] > 0:
            html += f'<div class="risk-bar critical" style="width: {critical_pct}%;">{stats["critical"]} Critical</div>'
        if stats['high'] > 0:
            html += f'<div class="risk-bar high" style="width: {high_pct}%;">{stats["high"]} High</div>'
        if stats['medium'] > 0:
            html += f'<div class="risk-bar medium" style="width: {medium_pct}%;">{stats["medium"]} Medium</div>'
        if stats['low'] > 0:
            html += f'<div class="risk-bar low" style="width: {low_pct}%;">{stats["low"]} Low</div>'
        html += '</div>'
        
        return html
    
    def _get_empty_report_html(self):
        """Generate HTML for when there are no findings."""
        # Encode logo
        logo_data_uri = ""
        if os.path.exists(_LOGO_PATH):
            with open(_LOGO_PATH, 'rb') as lf:
                logo_b64 = base64.b64encode(lf.read()).decode()
            logo_data_uri = f"data:image/png;base64,{logo_b64}"
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DIOGENES Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #2c3e50;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }}
        
        .main-container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .report-card {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 50px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320"><path fill="rgba(255,255,255,0.05)" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,122.7C672,117,768,139,864,154.7C960,171,1056,181,1152,165.3C1248,149,1344,107,1392,85.3L1440,64L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path></svg>') bottom center no-repeat;
            background-size: cover;
            opacity: 0.3;
        }}
        
        .logo-container {{
            display: inline-block;
            width: 120px;
            height: 120px;
            background: white;
            border-radius: 50%;
            padding: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
            position: relative;
            z-index: 1;
        }}
        
        .logo-container img {{
            width: 100%;
            height: 100%;
            object-fit: contain;
            border-radius: 50%;
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: -1px;
            position: relative;
            z-index: 1;
            text-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.95;
            font-weight: 300;
            letter-spacing: 2px;
            text-transform: uppercase;
            position: relative;
            z-index: 1;
        }}
        
        .timestamp {{
            color: rgba(255,255,255,0.8);
            font-size: 0.9em;
            margin-top: 20px;
            position: relative;
            z-index: 1;
        }}
        
        .content-section {{
            padding: 60px 40px;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 60px 20px;
        }}
        
        .success-icon {{
            width: 100px;
            height: 100px;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 50px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(17, 153, 142, 0.3);
        }}
        
        .no-findings h3 {{
            color: #11998e;
            margin-bottom: 15px;
            font-size: 2em;
            font-weight: 700;
        }}
        
        .no-findings p {{
            color: #7f8c8d;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .disclaimer {{
            background: linear-gradient(135deg, #f6f9fc 0%, #eef2f7 100%);
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-top: 40px;
            border-radius: 8px;
            text-align: left;
        }}
        
        .disclaimer strong {{
            display: block;
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px 40px;
            background: #f8f9fa;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        .footer p {{
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="main-container">
        <div class="report-card">
            <div class="header">
                <div class="logo-container">
                    {f'<img src="{logo_data_uri}" alt="DIOGENES Logo" />' if logo_data_uri else '<div style="font-size: 50px;">🔮</div>'}
                </div>
                <h1>DIOGENES</h1>
                <p class="subtitle">Web Application Security Assessment Report</p>
                <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
            
            <div class="content-section">
                <div class="no-findings">
                    <div class="success-icon">✓</div>
                    <h3>No Security Findings Detected</h3>
                    <p>No observable security signals were detected during this automated scan.</p>
                    
                    <div class="disclaimer">
                        <strong>Important Notice</strong>
                        <p>This report indicates no vulnerabilities were detected by automated scanning. However, this does not guarantee the complete absence of security issues. Manual security validation and penetration testing are strongly recommended for comprehensive security assessment.</p>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p><strong>DIOGENES</strong> - Searching for truth with a lamp, not a weapon.</p>
                <p>This report contains security observations that require manual verification.</p>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def _calculate_statistics(self, findings_list):
        """Calculate report statistics."""
        stats = {
            'total': len(findings_list),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'endpoints': len(set(f['endpoint'] for f in findings_list))
        }
        
        for finding in findings_list:
            vuln_type = finding['type']
            risk = self.RISK_LEVELS.get(vuln_type, {}).get('risk', 'Low')
            
            if risk == 'Critical':
                stats['critical'] += 1
            elif risk == 'High':
                stats['high'] += 1
            elif risk == 'Medium':
                stats['medium'] += 1
            else:
                stats['low'] += 1
        
        return stats
    
    def _generate_type_summary(self, by_type):
        """Generate summary table by vulnerability type."""
        html = '<table><thead><tr><th>Vulnerability Type</th><th>Risk Level</th><th>Count</th><th>CWE ID</th></tr></thead><tbody>'
        
        for vuln_type, findings in sorted(by_type.items()):
            risk_info = self.RISK_LEVELS.get(vuln_type, {'risk': 'Unknown', 'cweid': 'N/A'})
            risk = risk_info['risk']
            cweid = risk_info['cweid']
            count = len(findings)
            
            html += f'<tr><td><strong>{vuln_type.upper()}</strong></td><td><span class="risk-{risk.lower()}">{risk}</span></td><td>{count}</td><td><a href="https://cwe.mitre.org/data/definitions/{cweid}.html" target="_blank">CWE-{cweid}</a></td></tr>'
        
        html += '</tbody></table>'
        return html
    
    def _generate_endpoint_summary(self, by_endpoint):
        """Generate summary table by endpoint."""
        html = '<table><thead><tr><th>Endpoint</th><th>Finding Count</th><th>Vulnerability Types</th></tr></thead><tbody>'
        
        for endpoint, findings in sorted(by_endpoint.items()):
            types = set(f['type'] for f in findings)
            types_str = ', '.join(sorted(types))
            count = len(findings)
            
            html += f'<tr><td><span class="endpoint-tag">{endpoint}</span></td><td>{count}</td><td>{types_str}</td></tr>'
        
        html += '</tbody></table>'
        return html
    
    def _generate_detailed_findings(self, findings_list):
        """Generate detailed findings cards."""
        html = ''
        
        for idx, finding in enumerate(findings_list, 1):
            vuln_type = finding['type']
            risk_info = self.RISK_LEVELS.get(vuln_type, {'risk': 'Low', 'color': '#fbc02d'})
            risk = risk_info['risk'].lower()
            confidence = finding.get('confidence', 0.5)
            
            html += f'''<div class="finding-card {risk}">
                <div class="finding-header">
                    <div>
                        <span class="finding-type">{vuln_type.upper()}</span>
                        <span class="badge {risk}">{risk_info['risk']}</span>
                        <span class="confidence">Confidence: {confidence:.1%}</span>
                    </div>
                    <span>#{idx}</span>
                </div>
                
                <div class="finding-details">
                    <div class="detail-row">
                        <span class="detail-label">Endpoint:</span>
                        <span class="detail-value endpoint-tag">{finding.get('endpoint', 'N/A')}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Evidence:</span>
                        <span class="detail-value">{finding.get('evidence', 'No evidence provided')}</span>
                    </div>'''
            
            if finding.get('param'):
                html += f'''<div class="detail-row">
                        <span class="detail-label">Parameter:</span>
                        <span class="detail-value"><code>{finding['param']}</code></span>
                    </div>'''
            
            if finding.get('payload'):
                html += f'''<div class="detail-row">
                        <span class="detail-label">Payload:</span>
                        <div class="code-block">{finding['payload']}</div>
                    </div>'''
            
            if finding.get('context'):
                html += f'''<div class="detail-row">
                        <span class="detail-label">Context:</span>
                        <div class="code-block">{finding['context']}</div>
                    </div>'''
            
            if finding.get('status_code'):
                html += f'''<div class="detail-row">
                        <span class="detail-label">Status Code:</span>
                        <span class="detail-value">{finding['status_code']}</span>
                    </div>'''
            
            if finding.get('identity_a') or finding.get('identity_b'):
                html += f'''<div class="detail-row">
                        <span class="detail-label">Identities:</span>
                        <span class="detail-value">{finding.get('identity_a', 'N/A')} → {finding.get('identity_b', 'N/A')}</span>
                    </div>'''
            
            # Add remediation
            remediation_items = self.REMEDIATION.get(vuln_type, [])
            if remediation_items:
                html += '''<div class="remediation">
                    <h4>Recommended Remediation:</h4>
                    <ul>'''
                for item in remediation_items:
                    html += f'<li>{item}</li>'
                html += '''</ul></div>'''
            
            html += '''</div></div>'''
        
        return html

