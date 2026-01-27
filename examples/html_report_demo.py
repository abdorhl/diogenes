#!/usr/bin/env python3

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from reporting.reporter import Reporter
from core.models import Finding

def create_demo_findings():
    findings = [
        Finding(
            type="xss",
            endpoint="/search?q=",
            confidence=0.85,
            evidence="User input reflected in HTML context without encoding",
            param="q",
            payload="<img src=x onerror=alert(1)>",
            context="<div>Search results for: <img src=x onerror=alert(1)></div>",
            status_code=200
        ),
        Finding(
            type="sqli",
            endpoint="/user?id=",
            confidence=0.90,
            evidence="SQL error pattern detected in response",
            param="id",
            payload="1' OR '1'='1",
            context="SQL Error: You have an error in your SQL syntax; check the manual...",
            status_code=500
        ),
        Finding(
            type="csrf",
            endpoint="/settings",
            confidence=0.80,
            evidence="POST form detected without CSRF token protection",
            param=None,
            context="<form method='POST'><input name='email'></form>",
            status_code=200
        ),
        Finding(
            type="idor",
            endpoint="/profile?id=",
            confidence=0.95,
            evidence="Same sensitive data returned for different user IDs",
            param="id",
            identity_a="user123",
            identity_b="user456",
            context="Full profile including email and payment info visible to both identities",
            status_code=200
        ),
        Finding(
            type="reflection",
            endpoint="/api/search",
            confidence=0.65,
            evidence="Input marker reflected in JSON response",
            param="term",
            payload="bp_unique_marker_12345",
            context='{"results": [], "search_term": "bp_unique_marker_12345"}',
            status_code=200
        ),
        Finding(
            type="ssrf",
            endpoint="/proxy?url=",
            confidence=0.75,
            evidence="Server request reflection detected",
            param="url",
            payload="http://169.254.169.254/latest/meta-data/",
            context="Metadata endpoint accessible through proxy parameter",
            status_code=200
        ),
        Finding(
            type="state_change",
            endpoint="/api/delete",
            confidence=0.70,
            evidence="Destructive operation without state change protection",
            param=None,
            context="DELETE endpoint accepts GET requests without CSRF tokens",
            status_code=204
        ),
    ]
    return findings

def main():
    print("🔮 DIOGENES HTML Report Demo Generator")
    print("=" * 50)
    
    
    findings = create_demo_findings()
    print(f"\n✓ Created {len(findings)} demo findings")
    
    
    reporter = Reporter()
    output_file = "diogenes_demo_report.html"
    
    report_path = reporter.render_html(findings, output_file)
    print(f"✓ HTML report generated: {report_path}")
    print(f"\nOpen '{output_file}' in your web browser to view the report.")
    
    
    json_output = reporter.render_json(findings)
    json_file = "diogenes_demo_report.json"
    with open(json_file, 'w') as f:
        json.dump(json_output, f, indent=2)
    print(f"✓ JSON report generated: {json_file}")

if __name__ == "__main__":
    main()
