from rich.console import Console
from rich.table import Table
import json
import sys
from datetime import datetime
from collections import defaultdict
import base64

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
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DIOGENES Security Report</title>
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
            color: #333;
            background: #f5f5f5;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .timestamp {{
            color: rgba(255,255,255,0.8);
            font-size: 0.9em;
            margin-top: 10px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card h3 {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .summary-card.critical .value {{
            color: #b71c1c;
        }}
        
        .summary-card.high .value {{
            color: #d32f2f;
        }}
        
        .summary-card.medium .value {{
            color: #f57c00;
        }}
        
        .summary-card.low .value {{
            color: #fbc02d;
        }}
        
        .charts-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .chart-container h3 {{
            margin-bottom: 15px;
            color: #333;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .finding-card {{
            background: white;
            border-radius: 8px;
            border-left: 5px solid #667eea;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .finding-card.critical {{
            border-left-color: #b71c1c;
        }}
        
        .finding-card.high {{
            border-left-color: #d32f2f;
        }}
        
        .finding-card.medium {{
            border-left-color: #f57c00;
        }}
        
        .finding-card.low {{
            border-left-color: #fbc02d;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .finding-type {{
            font-weight: 700;
            font-size: 1.1em;
            text-transform: uppercase;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge.critical {{
            background: #ffebee;
            color: #b71c1c;
        }}
        
        .badge.high {{
            background: #ffebee;
            color: #d32f2f;
        }}
        
        .badge.medium {{
            background: #fff3e0;
            color: #f57c00;
        }}
        
        .badge.low {{
            background: #fffde7;
            color: #fbc02d;
        }}
        
        .confidence {{
            display: inline-block;
            margin-left: 10px;
            padding: 2px 8px;
            background: #e3f2fd;
            color: #1565c0;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        
        .finding-details {{
            margin-top: 10px;
            font-size: 0.95em;
        }}
        
        .detail-row {{
            margin-bottom: 8px;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: #666;
            display: inline-block;
            min-width: 100px;
        }}
        
        .detail-value {{
            color: #333;
            word-break: break-word;
        }}
        
        .code-block {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 5px;
        }}
        
        .remediation {{
            background: #e8f5e9;
            border: 1px solid #4caf50;
            border-radius: 4px;
            padding: 15px;
            margin-top: 15px;
        }}
        
        .remediation h4 {{
            color: #2e7d32;
            margin-bottom: 10px;
        }}
        
        .remediation ul {{
            margin-left: 20px;
            color: #333;
        }}
        
        .remediation li {{
            margin-bottom: 5px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        thead {{
            background: #667eea;
            color: white;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
        }}
        
        tbody tr:hover {{
            background: #fafafa;
        }}
        
        .risk-critical {{
            color: #b71c1c;
            font-weight: 600;
        }}
        
        .risk-high {{
            color: #d32f2f;
            font-weight: 600;
        }}
        
        .risk-medium {{
            color: #f57c00;
            font-weight: 600;
        }}
        
        .risk-low {{
            color: #fbc02d;
            font-weight: 600;
        }}
        
        .endpoint-tag {{
            background: #f0f0f0;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-family: monospace;
        }}
        
        .no-findings {{
            background: white;
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            color: #666;
        }}
        
        .no-findings h3 {{
            color: #4caf50;
            margin-bottom: 10px;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 0.9em;
            border-top: 1px solid #eee;
            margin-top: 40px;
        }}
        
        .toc {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .toc h3 {{
            margin-bottom: 15px;
        }}
        
        .toc ul {{
            list-style: none;
            margin-left: 0;
        }}
        
        .toc li {{
            margin-bottom: 8px;
        }}
        
        .toc a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        .toc a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔮 DIOGENES Security Report</h1>
        <p>Web Security Observation & Analysis</p>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
    
    <div class="container">
        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{stats['total']}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical Issues</h3>
                <div class="value">{stats['critical']}</div>
            </div>
            <div class="summary-card high">
                <h3>High Risk</h3>
                <div class="value">{stats['high']}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Risk</h3>
                <div class="value">{stats['medium']}</div>
            </div>
            <div class="summary-card low">
                <h3>Low Risk</h3>
                <div class="value">{stats['low']}</div>
            </div>
            <div class="summary-card">
                <h3>Affected Endpoints</h3>
                <div class="value">{stats['endpoints']}</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-section">
            <div class="chart-container">
                <h3>Findings by Risk Level</h3>
                <canvas id="riskChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Findings by Type</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>
        
        <!-- Table of Contents -->
        <div class="toc">
            <h3>Report Contents</h3>
            <ul>
                <li><a href="#by-type">Findings by Vulnerability Type</a></li>
                <li><a href="#by-endpoint">Findings by Endpoint</a></li>
                <li><a href="#detailed">Detailed Findings</a></li>
            </ul>
        </div>
        
        <!-- Findings by Type -->
        <div class="section" id="by-type">
            <h2 class="section-title">Findings by Vulnerability Type</h2>
            {self._generate_type_summary(by_type)}
        </div>
        
        <!-- Findings by Endpoint -->
        <div class="section" id="by-endpoint">
            <h2 class="section-title">Findings by Endpoint</h2>
            {self._generate_endpoint_summary(by_endpoint)}
        </div>
        
        <!-- Detailed Findings -->
        <div class="section" id="detailed">
            <h2 class="section-title">Detailed Security Findings</h2>
            {self._generate_detailed_findings(findings_list)}
        </div>
        
        <div class="footer">
            <p>DIOGENES - Searching for truth with a lamp, not a weapon.</p>
            <p>This report contains security observations. Manual verification is recommended.</p>
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
                    backgroundColor: ['#b71c1c', '#d32f2f', '#f57c00', '#fbc02d'],
                    borderColor: '#fff',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
        
        // Type Chart
        const typeCtx = document.getElementById('typeChart').getContext('2d');
        const typeLabels = {json.dumps(list(by_type.keys()))};
        const typeValues = {json.dumps([len(by_type[t]) for t in by_type.keys()])};
        const colors = ['#667eea', '#764ba2', '#f093fb', '#4b7bec', '#5f27cd', '#00d2d3', '#ff6348'];
        
        new Chart(typeCtx, {{
            type: 'bar',
            data: {{
                labels: typeLabels,
                datasets: [{{
                    label: 'Number of Findings',
                    data: typeValues,
                    backgroundColor: colors.slice(0, typeLabels.length),
                    borderRadius: 4,
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
                            stepSize: 1
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html
    
    def _get_empty_report_html(self):
        """Generate HTML for when there are no findings."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DIOGENES Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .timestamp {{
            color: rgba(255,255,255,0.8);
            font-size: 0.9em;
            margin-top: 10px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .no-findings {{
            background: white;
            border-radius: 8px;
            padding: 60px 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin: 40px 0;
        }}
        
        .no-findings h3 {{
            color: #4caf50;
            margin-bottom: 15px;
            font-size: 1.5em;
        }}
        
        .no-findings p {{
            color: #666;
            margin-bottom: 10px;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 0.9em;
            border-top: 1px solid #eee;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔮 DIOGENES Security Report</h1>
        <p>Web Security Observation & Analysis</p>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
    
    <div class="container">
        <div class="no-findings">
            <h3>✓ No Observable Security Signals Detected</h3>
            <p>No security observations were made during this scan.</p>
            <p style="font-size: 0.9em; color: #999;">This does not guarantee the absence of vulnerabilities.</p>
        </div>
        
        <div class="footer">
            <p>DIOGENES - Searching for truth with a lamp, not a weapon.</p>
            <p>This report contains security observations. Manual verification is recommended.</p>
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

