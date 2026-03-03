#!/usr/bin/env python3
"""
DIOGENES Interactive Console
Metasploit-style interface for web security scanning
"""

import cmd
import sys
import logging
import warnings
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import json

# Core imports
from core.session import Session
from core.crawler import Crawler
from core.engine import Engine
from core.config import load_config, SCAN_PROFILES
from reporting.reporter import Reporter

# Suppress INFO logs in console mode
logging.basicConfig(level=logging.WARNING, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Suppress urllib3 connection pool warnings
logging.getLogger('urllib3').setLevel(logging.ERROR)
warnings.filterwarnings('ignore', message='Connection pool is full')


class DiogenesConsole(cmd.Cmd):
    """Interactive console for DIOGENES security scanner"""
    
    intro = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ██╗ ██████╗  ██████╗ ███████╗███╗   ██╗███████╗  ║
║    ██╔══██╗██║██╔═══██╗██╔════╝ ██╔════╝████╗  ██║██╔════╝  ║
║    ██║  ██║██║██║   ██║██║  ███╗█████╗  ██╔██╗ ██║█████╗    ║
║    ██║  ██║██║██║   ██║██║   ██║██╔══╝  ██║╚██╗██║██╔══╝    ║
║    ██████╔╝██║╚██████╔╝╚██████╔╝███████╗██║ ╚████║███████╗  ║
║    ╚═════╝ ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝  ║
║                                                               ║
║         High-Performance Web Security Scanner v1.3           ║
║              Interactive Console (Metasploit Mode)           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Type 'help' or '?' for available commands.
Type 'show modules' to list available scan modules.
Type 'use <module>' to select a module, then 'run' to execute.
"""
    
    prompt = 'diogenes > '
    
    # Available modules
    MODULES = {
        'full': 'Full web application scan (all detectors)',
        'xss': 'XSS (Cross-Site Scripting) scanner',
        'sqli': 'SQL Injection scanner',
        'csrf': 'CSRF (Cross-Site Request Forgery) scanner',
        'ssrf': 'SSRF (Server-Side Request Forgery) scanner',
        'xxe': 'XXE (XML External Entity) scanner',
        'idor': 'IDOR (Insecure Direct Object Reference) scanner',
        'path_traversal': 'Path Traversal / Directory Traversal scanner',
        'cmd_injection': 'Command Injection scanner',
        'ssti': 'Server-Side Template Injection scanner',
        'nosql': 'NoSQL Injection scanner',
        'cors': 'CORS Misconfiguration scanner',
        'quick': 'Quick scan (fast, priority payloads only)',
        'stealth': 'Stealth scan (slow, evades detection)',
        'aggressive': 'Aggressive scan (fast, thorough)',
    }
    
    def __init__(self):
        super().__init__()
        self.current_module = None
        self.options = {
            'TARGET': {'value': '', 'required': True, 'description': 'Target URL to scan'},
            'DEPTH': {'value': '2', 'required': False, 'description': 'Crawl depth (1-5)'},
            'THREADS': {'value': '5', 'required': False, 'description': 'Number of concurrent threads'},
            'DELAY': {'value': '0', 'required': False, 'description': 'Delay between requests (seconds)'},
            'COOKIE': {'value': '', 'required': False, 'description': 'Session cookie (name=value;name=value)'},
            'HEADER': {'value': '', 'required': False, 'description': 'Custom headers (Name: Value; Name: Value)'},
            'IDENTITY_A': {'value': '', 'required': False, 'description': 'Path to identity A file (for IDOR)'},
            'IDENTITY_B': {'value': '', 'required': False, 'description': 'Path to identity B file (for IDOR)'},
            'OUTPUT': {'value': 'reports', 'required': False, 'description': 'Output directory for reports'},
        }
        self.scan_results = None
    
    def do_banner(self, arg):
        """Display the banner"""
        print(self.intro)
    
    def do_show(self, arg):
        """Show modules, options, or info
        Usage: show <modules|options|info|profiles>
        """
        if arg == 'modules':
            self._show_modules()
        elif arg == 'options':
            self._show_options()
        elif arg == 'info':
            self._show_info()
        elif arg == 'profiles':
            self._show_profiles()
        else:
            print("Usage: show <modules|options|info|profiles>")
    
    def do_use(self, arg):
        """Select a module
        Usage: use <module_name>
        Example: use xss
        """
        if not arg:
            print("Usage: use <module_name>")
            print("Type 'show modules' to see available modules")
            return
        
        if arg in self.MODULES:
            self.current_module = arg
            self.prompt = f'diogenes ({arg}) > '
            print(f"[+] Module selected: {arg}")
            print(f"[+] Description: {self.MODULES[arg]}")
            print("[*] Type 'show options' to see configuration")
            print("[*] Type 'run' to execute the scan")
        else:
            print(f"[-] Module '{arg}' not found")
            print("[*] Type 'show modules' to see available modules")
    
    def do_set(self, arg):
        """Set an option value
        Usage: set <option> <value>
        Example: set TARGET https://example.com
        """
        parts = arg.split(None, 1)
        if len(parts) != 2:
            print("Usage: set <option> <value>")
            return
        
        option_name, value = parts
        option_name = option_name.upper()
        
        if option_name in self.options:
            self.options[option_name]['value'] = value
            print(f"[+] {option_name} => {value}")
        else:
            print(f"[-] Unknown option: {option_name}")
            print("[*] Type 'show options' to see available options")
    
    def do_unset(self, arg):
        """Unset an option value
        Usage: unset <option>
        """
        option_name = arg.upper()
        if option_name in self.options:
            self.options[option_name]['value'] = ''
            print(f"[+] Unset {option_name}")
        else:
            print(f"[-] Unknown option: {option_name}")
    
    def do_run(self, arg):
        """Execute the current module
        Usage: run
        """
        if not self.current_module:
            print("[-] No module selected")
            print("[*] Type 'use <module>' to select a module")
            return
        
        # Validate required options
        missing = []
        for opt, config in self.options.items():
            if config['required'] and not config['value']:
                missing.append(opt)
        
        if missing:
            print(f"[-] Missing required options: {', '.join(missing)}")
            print("[*] Use 'set <option> <value>' to configure")
            return
        
        print("\n[*] Starting scan...")
        print(f"[*] Module: {self.current_module}")
        print(f"[*] Target: {self.options['TARGET']['value']}")
        print("[*] " + "=" * 60)
        
        try:
            self._execute_scan()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"[-] Scan failed: {e}")
            if '--debug' in sys.argv:
                import traceback
                traceback.print_exc()
    
    def do_back(self, arg):
        """Deselect the current module"""
        if self.current_module:
            print(f"[+] Deselected module: {self.current_module}")
            self.current_module = None
            self.prompt = 'diogenes > '
        else:
            print("[-] No module selected")
    
    def do_clear(self, arg):
        """Clear the screen"""
        import os
        os.system('cls' if sys.platform == 'win32' else 'clear')
    
    def do_exit(self, arg):
        """Exit the console"""
        print("[+] Exiting DIOGENES console. Stay secure! 🛡️")
        return True
    
    def do_quit(self, arg):
        """Exit the console"""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        """Exit on Ctrl+D"""
        print()
        return self.do_exit(arg)
    
    # Aliases
    do_q = do_quit
    do_x = do_exit
    
    # Helper methods
    
    def _show_modules(self):
        """Display available modules"""
        print("\nAvailable Modules:")
        print("=" * 70)
        for module, desc in self.MODULES.items():
            print(f"  {module:<30} {desc}")
        print("=" * 70)
        print()
    
    def _show_options(self):
        """Display current options"""
        if not self.current_module:
            print("[-] No module selected. Use 'use <module>' first")
            return
        
        print(f"\nModule options ({self.current_module}):")
        print("=" * 80)
        print(f"{'Option':<15} {'Current Value':<30} {'Required':<10} {'Description'}")
        print("-" * 80)
        
        for opt, config in self.options.items():
            required = 'yes' if config['required'] else 'no'
            value = config['value'] if config['value'] else ''
            print(f"{opt:<15} {value:<30} {required:<10} {config['description']}")
        
        print("=" * 80)
        print()
    
    def _show_info(self):
        """Show detailed module information"""
        if not self.current_module:
            print("[-] No module selected. Use 'use <module>' first")
            return
        
        print(f"\nModule: {self.current_module}")
        print("=" * 70)
        print(f"Description: {self.MODULES[self.current_module]}")
        print()
        
        # Module-specific info
        if 'xss' in self.current_module:
            print("Detection Methods:")
            print("  - Reflected XSS (payload echoed in response)")
            print("  - Stored XSS (payload persists)")
            print("  - DOM-based XSS (client-side sinks)")
            print("  - Context detection (HTML, attributes, scripts)")
        elif 'sqli' in self.current_module:
            print("Detection Methods:")
            print("  - Error-based SQLi (SQL errors in response)")
            print("  - Union-based SQLi (result set manipulation)")
            print("  - Boolean-based blind SQLi (true/false responses)")
            print("  - Time-based blind SQLi (response delays)")
            print("  - Database fingerprinting (MySQL, PostgreSQL, MSSQL, etc.)")
        elif 'idor' in self.current_module:
            print("Detection Methods:")
            print("  - Horizontal privilege escalation (same role, different user)")
            print("  - Vertical privilege escalation (different roles)")
            print("  - Content similarity analysis")
            print("\nNote: Requires IDENTITY_A and IDENTITY_B to be set")
        elif 'xxe' in self.current_module:
            print("Detection Methods:")
            print("  - Classic XXE (file disclosure)")
            print("  - SSRF via XXE (internal network access)")
            print("  - XInclude attacks")
            print("  - SOAP XXE")
            print("  - SVG upload XXE")
        
        print("=" * 70)
        print()
    
    def _show_profiles(self):
        """Show available scan profiles"""
        print("\nAvailable Scan Profiles:")
        print("=" * 70)
        for profile_name, config in SCAN_PROFILES.items():
            print(f"\n  {profile_name.upper()}")
            print(f"    Delay: {config.delay}s")
            print(f"    Threads: {config.max_concurrent}")
            print(f"    Depth: {config.max_depth}")
            print(f"    Quick Scan: {config.quick_scan}")
        print("\n" + "=" * 70)
        print()
    
    def _execute_scan(self):
        """Execute the actual scan"""
        target = self.options['TARGET']['value']
        depth = int(self.options['DEPTH']['value'])
        threads = int(self.options['THREADS']['value'])
        delay = float(self.options['DELAY']['value'])
        
        # Parse cookies and headers
        cookies = self._parse_cookies(self.options['COOKIE']['value'])
        headers = self._parse_headers(self.options['HEADER']['value'])
        
        # Create session
        print("[*] Creating session...")
        main_session = Session("primary", target, cookies=cookies, headers=headers, delay=delay)
        
        # Load identities for IDOR (if provided)
        identity_a, identity_b = None, None
        if self.options['IDENTITY_A']['value'] and self.options['IDENTITY_B']['value']:
            try:
                identity_a, identity_b = self._load_identities(
                    self.options['IDENTITY_A']['value'],
                    self.options['IDENTITY_B']['value'],
                    target, delay
                )
                print("[+] Loaded two identities for IDOR testing")
            except Exception as e:
                print(f"[!] Failed to load identities: {e}")
        
        # Crawl
        print("[*] Crawling target...")
        crawler = Crawler(main_session, max_depth=depth)
        crawler.crawl()
        print(f"[+] Found {len(crawler.endpoints)} endpoints")
        
        # Determine which detectors to enable based on module
        enabled_detectors = self._get_detectors_for_module()
        quick_scan = 'quick' in self.current_module
        
        # Run scan
        print(f"[*] Running detectors: {', '.join(enabled_detectors)}")
        engine = Engine(
            main_session,
            identity_a=identity_a,
            identity_b=identity_b,
            enabled_detectors=enabled_detectors,
            max_workers=threads,
            concurrent=True,
            quick_scan=quick_scan
        )
        engine.run(crawler.endpoints)
        
        # Store results
        self.scan_results = engine.findings
        
        # Display results
        print("\n" + "=" * 70)
        print(f"[+] Scan complete! Found {len(engine.findings)} security issues")
        print("=" * 70)
        
        if engine.findings:
            reporter = Reporter()
            reporter.render(engine.findings)
            
            # Save HTML report
            output_dir = Path(self.options['OUTPUT']['value'])
            output_dir.mkdir(parents=True, exist_ok=True)
            
            report_path = self._build_report_path(target, output_dir)
            html_report = reporter.render_html(engine.findings, report_path)
            print(f"\n[+] HTML report saved: {html_report}")
            
            # Save PDF
            try:
                pdf_path = report_path.replace('.html', '.pdf')
                pdf_report = reporter.render_pdf(engine.findings, pdf_path, target_url=target)
                print(f"[+] PDF report saved: {pdf_report}")
            except Exception as e:
                print(f"[!] PDF generation failed: {e}")
        else:
            print("\n[*] No vulnerabilities found")
        
        print()
    
    def _get_detectors_for_module(self):
        """Get list of detectors based on selected module"""
        module = self.current_module
        
        if module == 'full':
            return ['xss', 'sqli', 'csrf', 'ssrf', 'xxe', 'idor', 'path_traversal', 'command_injection', 'ssti', 'nosql', 'cors']
        elif module == 'xss':
            return ['xss']
        elif module == 'sqli':
            return ['sqli']
        elif module == 'csrf':
            return ['csrf']
        elif module == 'ssrf':
            return ['ssrf']
        elif module == 'xxe':
            return ['xxe']
        elif module == 'idor':
            return ['idor']
        elif module == 'path_traversal':
            return ['path_traversal']
        elif module == 'cmd_injection':
            return ['command_injection']
        elif module == 'ssti':
            return ['ssti']
        elif module == 'nosql':
            return ['nosql']
        elif module == 'cors':
            return ['cors']
        else:
            # quick, stealth, aggressive - run all
            return ['xss', 'sqli', 'csrf', 'ssrf', 'xxe', 'idor', 'path_traversal', 'command_injection', 'ssti', 'nosql', 'cors']
    
    def _parse_cookies(self, cookie_str):
        """Parse cookie string"""
        cookies = {}
        if not cookie_str:
            return cookies
        for item in cookie_str.split(";"):
            item = item.strip()
            if "=" in item:
                name, value = item.split("=", 1)
                cookies[name.strip()] = value.strip()
        return cookies
    
    def _parse_headers(self, header_str):
        """Parse header string"""
        headers = {}
        if not header_str:
            return headers
        for item in header_str.split(";"):
            item = item.strip()
            if ":" in item:
                name, value = item.split(":", 1)
                headers[name.strip()] = value.strip()
        return headers
    
    def _load_identities(self, path_a, path_b, target, delay):
        """Load identity files for IDOR testing"""
        data_a = json.loads(Path(path_a).read_text())
        data_b = json.loads(Path(path_b).read_text())
        
        cookies_a = data_a.get("cookies", data_a) if "cookies" in data_a else data_a
        headers_a = data_a.get("headers", {})
        cookies_b = data_b.get("cookies", data_b) if "cookies" in data_b else data_b
        headers_b = data_b.get("headers", {})
        
        identity_a = Session("identity_a", target, cookies=cookies_a, headers=headers_a, delay=delay)
        identity_b = Session("identity_b", target, cookies=cookies_b, headers=headers_b, delay=delay)
        
        return identity_a, identity_b
    
    def _build_report_path(self, url, output_dir):
        """Build report file path"""
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        host = host.split(":")[0]
        import re
        safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", host) or "target"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_host}_{timestamp}.html"
        return str(output_dir / filename)
    
    # Command completion
    def complete_use(self, text, line, begidx, endidx):
        """Tab completion for 'use' command"""
        return [m for m in self.MODULES.keys() if m.startswith(text)]
    
    def complete_show(self, text, line, begidx, endidx):
        """Tab completion for 'show' command"""
        options = ['modules', 'options', 'info', 'profiles']
        return [o for o in options if o.startswith(text)]
    
    def complete_set(self, text, line, begidx, endidx):
        """Tab completion for 'set' command"""
        return [o for o in self.options.keys() if o.startswith(text.upper())]
    
    def complete_unset(self, text, line, begidx, endidx):
        """Tab completion for 'unset' command"""
        return [o for o in self.options.keys() if o.startswith(text.upper())]


def main():
    """Main entry point for interactive console"""
    console = DiogenesConsole()
    
    # Check for debug mode
    if '--debug' in sys.argv:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n[+] Exiting DIOGENES console. Stay secure! 🛡️")
        sys.exit(0)


if __name__ == '__main__':
    main()
