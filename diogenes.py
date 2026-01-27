import argparse
import json
import logging
import sys
import warnings
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import re
from core.session import Session
from core.crawler import Crawler
from core.engine import Engine
from reporting.reporter import Reporter

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def parse_cookies(cookie_str: str) -> dict:
    cookies = {}
    if not cookie_str:
        return cookies
    for item in cookie_str.split(";"):
        item = item.strip()
        if "=" in item:
            name, value = item.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies

def parse_headers(header_str: str) -> dict:
    headers = {}
    if not header_str:
        return headers
    for item in header_str.split(";"):
        item = item.strip()
        if ":" in item:
            name, value = item.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers

def build_report_path(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    host = host.split(":")[0]
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", host) or "target"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{safe_host}_{timestamp}.html"
    return str(reports_dir / filename)

def main():
    parser = argparse.ArgumentParser(
        prog="DIOGENES",
        description="Safe security observation tool for developers. Detects XSS, SQLi, CSRF, SSRF, IDOR signals.",
        epilog="Example: python diogenes.py https://target.local --depth 2 --cookie 'session=abc123'"
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads for scanning (default: 5)")
    parser.add_argument("--no-concurrent", action="store_true", help="Disable concurrent scanning (use sequential mode)")
    parser.add_argument("--endpoints-file", help="File with list of endpoints to test (one per line)")
    parser.add_argument("--cookie", help="Session cookie string (name=value;name=value)")
    parser.add_argument("--header", help="Custom headers (Name: Value; Name: Value)")
    parser.add_argument("--identity-a", help="Path to file with identity A cookies")
    parser.add_argument("--identity-b", help="Path to file with identity B cookies")
    parser.add_argument("--output", choices=["table", "json"], default="table", help="Output format (default: table)")
    parser.add_argument("--html", help="Optional custom HTML report path (default: reports/<site>_<timestamp>.html)")
    parser.add_argument("--detectors", default="all", help="Detectors to run (xss,sqli,csrf,ssrf,idor,all). Default: all")
    parser.add_argument("--test-findings", action="store_true", help="Add test finding for validation")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"DIOGENES starting scan on {args.url}")
    
    try:
        # Parse cookies and headers
        cookies = parse_cookies(args.cookie) if args.cookie else {}
        headers = parse_headers(args.header) if args.header else {}
        
        # Create main session with rate limiting
        main_session = Session("primary", args.url, cookies=cookies, headers=headers, delay=args.delay)
        
        # Load identity sessions if provided (support both cookies-only and cookies+headers format)
        identity_a = None
        identity_b = None
        if args.identity_a and args.identity_b:
            try:
                data_a = json.loads(Path(args.identity_a).read_text())
                data_b = json.loads(Path(args.identity_b).read_text())
                
                # Support legacy format (flat dict = cookies) and new format {cookies: {}, headers: {}}
                cookies_a = data_a.get("cookies", data_a) if "cookies" in data_a else data_a
                headers_a = data_a.get("headers", {})
                cookies_b = data_b.get("cookies", data_b) if "cookies" in data_b else data_b
                headers_b = data_b.get("headers", {})
                
                identity_a = Session("identity_a", args.url, cookies=cookies_a, headers=headers_a, delay=args.delay)
                identity_b = Session("identity_b", args.url, cookies=cookies_b, headers=headers_b, delay=args.delay)
                logger.info("Loaded two identities for IDOR testing")
            except Exception as e:
                logger.warning(f"Failed to load identities: {e}")
        
        # Crawl
        logger.info("Crawling target...")
        crawler = Crawler(main_session, max_depth=args.depth)
        crawler.crawl()
        
        # Load additional endpoints from file if provided
        if args.endpoints_file:
            try:
                with open(args.endpoints_file, 'r') as f:
                    file_endpoints = [line.strip() for line in f if line.strip()]
                    # Normalize endpoints to full URLs
                    for ep in file_endpoints:
                        if ep.startswith('http://') or ep.startswith('https://'):
                            crawler.endpoints.add(ep)
                        else:
                            # Relative path - prepend base URL
                            if not ep.startswith('/'):
                                ep = '/' + ep
                            full_url = args.url.rstrip('/') + ep
                            crawler.endpoints.add(full_url)
                    logger.info(f"Loaded {len(file_endpoints)} endpoints from {args.endpoints_file}")
            except Exception as e:
                logger.warning(f"Failed to load endpoints file: {e}")
        
        logger.info(f"Found {len(crawler.endpoints)} total endpoints")
        
        # Run detectors
        logger.info("Running detectors...")
        enabled_detectors = args.detectors.lower().split(",") if args.detectors != "all" else ["xss", "sqli", "csrf", "ssrf", "idor"]
        enabled_detectors = [d.strip() for d in enabled_detectors]
        
        engine = Engine(
            main_session, 
            identity_a=identity_a, 
            identity_b=identity_b, 
            enabled_detectors=enabled_detectors,
            max_workers=args.threads,
            concurrent=not args.no_concurrent
        )
        engine.run(crawler.endpoints)
        
        if args.test_findings:
            engine.findings.append({
                "type": "reflection",
                "endpoint": "/test",
                "evidence": "Test marker reflected in response",
                "confidence": 0.99
            })
        
        logger.info(f"Found {len(engine.findings)} security signals")
        
        reporter = Reporter()

        # Render output
        if args.output == "json":
            output = {
                "tool": "DIOGENES",
                "target": args.url,
                "endpoints_found": len(crawler.endpoints),
                "findings": [f if isinstance(f, dict) else f.to_dict() for f in engine.findings],
            }
            print(json.dumps(output, indent=2))
        else:
            reporter.render(engine.findings)

        # Always generate HTML report
        report_path = args.html or build_report_path(args.url)
        report_file = reporter.render_html(engine.findings, report_path)
        logger.info(f"HTML report generated: {report_file}")
    
    except KeyboardInterrupt:
        print()  # New line after ^C
        logger.warning("[!] Scan interrupted by user")
        # Suppress threading cleanup warnings
        warnings.filterwarnings("ignore", category=ResourceWarning)
        os._exit(0)  # Exit immediately without cleanup
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
