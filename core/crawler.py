
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import threading
from functools import lru_cache

logger = logging.getLogger(__name__)


class Crawler:
    # Compiled regex patterns for better performance
    ENDPOINT_PATTERNS = [
        re.compile(r"(?i)\bfetch\(\s*['\"]([^'\"]+)['\"]"),
        re.compile(r"(?i)\baxios\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"),
        re.compile(r"(?i)\bxmlhttprequest\b[\s\S]{0,200}open\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"]"),
        re.compile(r"['\"](/(?:api|rest|graphql|v1|v2)/[^'\"\s<>]{1,200})['\"]"),
    ]
    
    def __init__(self, session, max_depth=3, same_host_only=True, max_workers=10, max_urls=500):
        self.session = session
        self.visited = set()
        self.visited_lock = threading.Lock()
        self.endpoints = []
        self.endpoints_lock = threading.Lock()
        self.max_depth = max_depth
        self.same_host_only = same_host_only
        self.base_url = session.base_url
        self.base_host = urlparse(self.base_url).netloc
        self.max_workers = max_workers
        self.max_urls = max_urls
        self.url_queue = Queue()

        # Keep endpoint list unique while preserving order
        self._endpoints_seen = set()

    def _add_endpoint(self, url: str) -> None:
        if not url:
            return
        norm = self._normalize_url(url)
        with self.endpoints_lock:
            if norm in self._endpoints_seen:
                return
            self._endpoints_seen.add(norm)
            self.endpoints.append(norm)

    def crawl(self, start_path="/"):
        """Main entry point - uses breadth-first crawling with concurrency"""
        self.url_queue.put((start_path, 0))
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = set()
            
            while not self.url_queue.empty() or futures:
                # Check if we've hit the URL limit
                with self.visited_lock:
                    if len(self.visited) >= self.max_urls:
                        logger.debug(f"Reached max URLs limit ({self.max_urls})")
                        break
                
                # Submit new tasks up to max_workers
                while len(futures) < self.max_workers and not self.url_queue.empty():
                    try:
                        url, depth = self.url_queue.get_nowait()
                        if depth <= self.max_depth:
                            future = executor.submit(self._crawl_page, url, depth)
                            futures.add(future)
                    except:
                        break
                
                # Process completed futures
                if futures:
                    done = set()
                    try:
                        for future in as_completed(futures, timeout=0.1):
                            done.add(future)
                            try:
                                future.result()
                            except Exception as e:
                                logger.debug(f"Crawl error: {e}")
                    except TimeoutError:
                        pass  # Some futures still pending, that's ok
                    futures = futures - done

    def _crawl_page(self, path, depth):
        """Crawl a single page (thread-safe)"""
        url = urljoin(self.base_url, path) if not path.startswith("http") else path
        norm_url = self._normalize_url(url)
        
        # Thread-safe check and add to visited
        with self.visited_lock:
            if norm_url in self.visited or len(self.visited) >= self.max_urls:
                return
            self.visited.add(norm_url)
        
        logger.debug(f"Crawling (depth {depth}): {url}")
        
        try:
            res = self.session.get(norm_url)
            if not res or res.status_code >= 400:
                logger.debug(f"Failed to fetch {url}: {res.status_code if res else 'None'}")
                return
            
            # Check response size to avoid processing huge responses
            try:
                content_length = len(res.content or b"")
                if content_length > 2 * 1024 * 1024:  # 2MB limit
                    logger.debug(f"Skipping large response ({content_length} bytes): {url}")
                    return
            except:
                pass
                
        except Exception as e:
            logger.debug(f"Exception crawling {url}: {e}")
            return

        # Include the page we successfully crawled as a testable endpoint.
        self._add_endpoint(norm_url)

        # Seed additional endpoints from robots.txt / sitemap.xml only from the start page.
        if depth == 0:
            self._seed_from_robots_and_sitemap(parent_url=norm_url)
        
        self._parse_links(res.text, norm_url, depth)

        # SPAs often keep backend endpoints in JS bundles; extract and queue them.
        self._parse_scripts_for_endpoints(res.text, norm_url, depth)

    def _parse_links(self, html, parent_url, depth):
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return

        # Extract <a href>
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if not href or href.startswith("#"):
                continue
            full_url = urljoin(parent_url, href)
            if self._should_visit(full_url):
                self._add_endpoint(full_url)
                self.url_queue.put((full_url, depth + 1))

        # Extract <form action>
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if not action:
                # If no action, form posts to itself
                action = urlparse(parent_url).path
            
            method = form.get("method", "GET").upper()
            form_url = urljoin(parent_url, action)
            if self._should_visit(form_url):
                # Add query params from <input name=...>
                params = []
                for inp in form.find_all("input", attrs={"name": True}):
                    params.append(f"{inp['name']}=*")
                if params:
                    form_url_with_params = form_url + ("?" if "?" not in form_url else "&") + "&".join(params)
                else:
                    form_url_with_params = form_url
                self._add_endpoint(form_url_with_params)
                self.url_queue.put((form_url, depth + 1))

    def _parse_scripts_for_endpoints(self, html, parent_url, depth):
        if not html or depth > self.max_depth:
            return

        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return

        # Inline scripts
        for script in soup.find_all("script"):
            js = script.string or script.get_text() or ""
            for candidate in self._extract_endpoint_candidates(js):
                full_url = urljoin(parent_url, candidate)
                if self._should_visit(full_url):
                    self._add_endpoint(full_url)

        # External bundles - fetch concurrently (limit to keep scans fast)
        script_urls = []
        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if src and self._should_fetch_resource(urljoin(parent_url, src)):
                script_urls.append(urljoin(parent_url, src))
                if len(script_urls) >= 5:
                    break
        
        if script_urls:
            self._fetch_scripts_concurrently(script_urls, parent_url)

    def _fetch_scripts_concurrently(self, script_urls, parent_url):
        """Fetch multiple JS bundles in parallel"""
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_map = {executor.submit(self._fetch_script, url): url for url in script_urls}
            
            for future in as_completed(future_map, timeout=15):
                try:
                    script_text = future.result()
                    if script_text:
                        for candidate in self._extract_endpoint_candidates(script_text):
                            full_url = urljoin(parent_url, candidate)
                            if self._should_visit(full_url):
                                self._add_endpoint(full_url)
                except Exception as e:
                    logger.debug(f"Script fetch error: {e}")
    
    def _fetch_script(self, url):
        """Fetch a single script with size limits"""
        try:
            res = self.session.get(url)
            if not res or res.status_code >= 400:
                return None
            
            # Check size
            content_len = len(res.content or b"")
            if content_len > 1024 * 1024:  # 1MB limit for scripts
                return None
            
            # Check content type
            ct = res.headers.get("Content-Type", "").lower()
            if ct and ("javascript" not in ct and "text" not in ct and "json" not in ct):
                return None
            
            return res.text
        except Exception:
            return None

    def _extract_endpoint_candidates(self, text: str):
        if not text:
            return []

        candidates = []
        # Use compiled patterns for better performance
        for pattern in self.ENDPOINT_PATTERNS:
            for match in pattern.findall(text):
                if not match:
                    continue
                # Filter obviously irrelevant schemes
                if match.startswith(("mailto:", "tel:", "javascript:")):
                    continue
                # Only keep same-site relative paths or same-host absolute URLs
                if match.startswith("http://") or match.startswith("https://"):
                    if urlparse(match).netloc != self.base_host:
                        continue
                candidates.append(match)

        # De-dup while preserving order
        seen = set()
        out = []
        for c in candidates:
            if c in seen:
                continue
            seen.add(c)
            out.append(c)
        return out

    def _seed_from_robots_and_sitemap(self, parent_url: str):
        # robots.txt
        try:
            robots_url = urljoin(parent_url, "/robots.txt")
            r = self.session.get(robots_url)
            if r and r.status_code < 400:
                disallow_added = 0
                for line in (r.text or "").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("sitemap:"):
                        _, value = line.split(":", 1)
                        sm = value.strip()
                        if sm:
                            self._seed_from_sitemap(sm, parent_url)
                    if line.lower().startswith("disallow:"):
                        _, value = line.split(":", 1)
                        path = value.strip()
                        if path.startswith("/"):
                            full = urljoin(parent_url, path)
                            if self._should_visit(full):
                                self._add_endpoint(full)
                                disallow_added += 1
                                if disallow_added >= 30:
                                    break
        except Exception:
            pass

        # sitemap.xml (common default)
        try:
            self._seed_from_sitemap(urljoin(parent_url, "/sitemap.xml"), parent_url)
        except Exception:
            pass

    def _seed_from_sitemap(self, sitemap_url: str, parent_url: str):
        try:
            sm_url = sitemap_url
            if not sm_url.startswith(("http://", "https://")):
                sm_url = urljoin(parent_url, sm_url)
            if urlparse(sm_url).netloc != self.base_host:
                return
            res = self.session.get(sm_url)
            if not res or res.status_code >= 400:
                return

            # Basic <loc> extraction (works for sitemapindex + urlset)
            added = 0
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", res.text or "", flags=re.IGNORECASE):
                full = loc.strip()
                if not full:
                    continue
                if self._should_visit(full):
                    self._add_endpoint(full)
                    added += 1
                    if added >= 200:
                        break
        except Exception:
            return

    def _should_fetch_resource(self, url: str) -> bool:
        # Only fetch same-host resources and avoid obviously huge binaries.
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.base_host:
            return False
        path = (parsed.path or "").lower()
        blocked_ext = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3")
        return not path.endswith(blocked_ext)

    def _should_visit(self, url):
        norm_url = self._normalize_url(url)
        with self.visited_lock:
            if norm_url in self.visited:
                return False
        if self.same_host_only:
            host = urlparse(url).netloc
            if host and host != self.base_host:
                return False
        return True

    @lru_cache(maxsize=10000)
    def _normalize_url(self, url):
        # Remove fragment, sort query params
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            q = "&".join(sorted(parsed.query.split("&")))
            return f"{base}?{q}"
        return base
