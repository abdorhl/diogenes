# Example usage commands for DIOGENES

## Basic scan
python diogenes.py https://target.local

## ⚡ Quick scan (Smart early-exit for large applications)
python diogenes.py https://target.local --quick-scan --threads 10

## With cookies
python diogenes.py https://target.local --cookie "session=abc123;token=xyz"

## With custom headers
python diogenes.py https://target.local --header "Authorization: Bearer token123"

## Deeper crawl
python diogenes.py https://target.local --depth 4

## Two-identity IDOR testing
python diogenes.py https://target.local \
  --identity-a examples/identity_a.json \
  --identity-b examples/identity_b.json

## JSON output (CI/CD friendly)
python diogenes.py https://target.local --output json > report.json

## HTML Report (Auto-generated)
python diogenes.py https://target.local

This generates a beautiful, interactive HTML report with:
- Executive summary dashboard with statistics
- Charts showing vulnerability distribution by risk level and type
- Detailed findings with evidence and context
- Remediation guidance for each vulnerability class
- CWE references for further research
- Affected endpoints grouped by location

Reports are saved to:
`reports/<website>_<timestamp>.html`

To override the default location:

python diogenes.py https://target.local --html custom_report.html

## Combining HTML report with other options
python diogenes.py https://target.local \
  --depth 3 \
  --cookie "session=abc123" \
  --identity-a examples/identity_a.json \
  --identity-b examples/identity_b.json \
  --html security_report.html

## Verbose logging
python diogenes.py https://target.local --verbose

## All options
python diogenes.py https://target.local \
  --depth 3 \
  --cookie "session=abc123" \
  --header "Authorization: Bearer token" \
  --identity-a examples/identity_a.json \
  --identity-b examples/identity_b.json \
  --output json \
  --html detailed_report.html \
  --verbose

## Demo: Generate sample HTML report without scanning
python examples/html_report_demo.py

This creates sample findings and generates demo HTML and JSON reports
useful for testing the reporting functionality.
