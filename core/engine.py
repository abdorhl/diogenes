import signal
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from detectors.reflection import ReflectionDetector
from detectors.idor import IDORDetector
from detectors.state_change import StateChangeDetector
from detectors.xss import XSSDetector
from detectors.sqli import SQLiDetector
from detectors.csrf import CSRFDetector
from detectors.ssrf import SSRFDetector
from detectors.xxe import XXEDetector

logger = logging.getLogger(__name__)


class Engine:
    # Common paths to try as fallback discovery
    COMMON_PATHS = [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/api",
        "/rest",
        "/graphql",
    ]
    
    def __init__(self, session, identity_a=None, identity_b=None, enabled_detectors=None, max_workers=5, concurrent=True, quick_scan=False):
        self.session = session
        self.findings = []
        self.max_workers = max_workers
        self.concurrent = concurrent
        self.interrupted = False
        self.quick_scan = quick_scan
        self.scanned_count = 0
        self.total_endpoints = 0
        
        # Default to all detectors if not specified
        if enabled_detectors is None:
            enabled_detectors = ["xss", "sqli", "csrf", "ssrf", "idor", "xxe"]
        self.enabled = [d.lower() for d in enabled_detectors]

        self.reflection = ReflectionDetector(session)
        self.xss = XSSDetector(session, quick_mode=quick_scan) if "xss" in self.enabled else None
        self.sqli = SQLiDetector(session, quick_mode=quick_scan) if "sqli" in self.enabled else None
        self.csrf = CSRFDetector(session) if "csrf" in self.enabled else None
        self.ssrf = SSRFDetector(session, quick_mode=quick_scan) if "ssrf" in self.enabled else None
        self.xxe = XXEDetector(session, quick_mode=quick_scan) if "xxe" in self.enabled else None
        self.idor = IDORDetector(identity_a, identity_b) if "idor" in self.enabled and identity_a and identity_b else None
        self.state = StateChangeDetector()


    def run(self, endpoints):
        # Add common paths as fallback if crawl found few endpoints,
        # but only keep paths that actually exist to reduce noise.
        if len(endpoints) < 3:
            for path in self.COMMON_PATHS:
                full_url = self.session.base_url + path
                if full_url in endpoints:
                    continue
                try:
                    res = self.session.get(full_url)
                except Exception:
                    res = None
                if res and res.status_code < 400:
                    endpoints.append(full_url)
        
        self.total_endpoints = len(endpoints)
        
        # Concurrent scanning for better performance
        if self.concurrent and len(endpoints) > 1:
            executor = ThreadPoolExecutor(max_workers=self.max_workers)
            try:
                futures = {executor.submit(self._scan_endpoint, ep): ep for ep in endpoints}
                for future in as_completed(futures):
                    if self.interrupted:
                        break
                    try:
                        future.result()  # Findings are appended in _scan_endpoint
                    except Exception as e:
                        # Silent failure per endpoint to continue scanning
                        pass
            except KeyboardInterrupt:
                self.interrupted = True
                # Cancel all remaining futures
                for future in futures:
                    future.cancel()
                # Shutdown without waiting for threads to finish
                executor.shutdown(wait=False, cancel_futures=True)
                raise
            finally:
                if not self.interrupted:
                    executor.shutdown(wait=True)
        else:
            # Sequential scanning (safer for rate-limited targets)
            for ep in endpoints:
                if self.interrupted:
                    break
                try:
                    self._scan_endpoint(ep)
                except KeyboardInterrupt:
                    self.interrupted = True
                    raise
                except Exception:
                    pass
    
    def _scan_endpoint(self, ep):
        """Run all enabled detectors on a single endpoint"""
        self.scanned_count += 1
        if self.scanned_count % 10 == 0 or self.scanned_count == self.total_endpoints:
            logger.info(f"Progress: {self.scanned_count}/{self.total_endpoints} endpoints scanned, {len(self.findings)} findings")
        
        self._run_reflection(ep)
        if self.xss:
            self._run_xss(ep)
        if self.sqli:
            self._run_sqli(ep)
        if self.ssrf:
            self._run_ssrf(ep)
        if self.xxe:
            self._run_xxe(ep)
        if self.csrf:
            self._run_csrf(ep)
        self._run_state(ep)
        if self.idor:
            self._run_idor(ep)
    def _run_sqli(self, ep):
        for param in ["q", "search", "id"]:
            result = self.sqli.test(ep, param)
            if result:
                self.findings.append(result)

    def _run_ssrf(self, ep):
        for param in ["q", "search", "id"]:
            result = self.ssrf.test(ep, param)
            if result:
                self.findings.append(result)

    def _run_csrf(self, ep):
        result = self.csrf.test(ep)
        if result:
            self.findings.append(result)


    def _run_reflection(self, ep):
        for param in ["q", "search", "id"]:  # heuristic
            result = self.reflection.test(ep, param)
            if result:
                self.findings.append(result)

    def _run_xss(self, ep):
        # Pass None to test all common parameter names
        result = self.xss.test(ep, param=None)
        if result:
            self.findings.append(result)

    def _run_xxe(self, ep):
        for param in ["xml", "data", "content"]:
            result = self.xxe.test(ep, param)
            if result:
                self.findings.append(result)

    def _run_idor(self, ep):
        result = self.idor.test(ep)
        if result:
            self.findings.append(result)

    def _run_state(self, ep):
        result = self.state.analyze(ep)
        if result:
            self.findings.append(result)
