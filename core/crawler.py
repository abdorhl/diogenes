
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import re

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, session, max_depth=3, same_host_only=True):
        self.session = session
        self.visited = set()
        self.endpoints = []
        self.max_depth = max_depth
        self.same_host_only = same_host_only
        self.base_url = session.base_url
        self.base_host = urlparse(self.base_url).netloc

        # Keep endpoint list unique while preserving order
        self._endpoints_seen = set()

    def _add_endpoint(self, url: str) -> None:
        if not url:
            return
        norm = self._normalize_url(url)
        if norm in self._endpoints_seen:
            return
        self._endpoints_seen.add(norm)
        self.endpoints.append(norm)

    def crawl(self, path="/", depth=0):
        url = urljoin(self.base_url, path) if not path.startswith("http") else path
        norm_url = self._normalize_url(url)
        
        if norm_url in self.visited or depth > self.max_depth:
            return

        self.visited.add(norm_url)
        logger.debug(f"Crawling (depth {depth}): {url}")
        
        try:
            res = self.session.get(norm_url)
            if not res or res.status_code >= 400:
                logger.debug(f"Failed to fetch {url}: {res.status_code if res else 'None'}")
                return
        except Exception as e:
            logger.debug(f"Exception crawling {url}: {e}")
            return

        # Include the page we successfully crawled as a testable endpoint.
        # This avoids 0-endpoint scans on SPAs that don't expose server URLs in <a>/<form>.
        self._add_endpoint(norm_url)

        # Seed additional endpoints from robots.txt / sitemap.xml only from the start page.
        if depth == 0:
            self._seed_from_robots_and_sitemap(parent_url=norm_url)
        
        self._parse_links(res.text, norm_url, depth)

        # SPAs often keep backend endpoints in JS bundles; extract and queue them.
        self._parse_scripts_for_endpoints(res.text, norm_url, depth)

    def _parse_links(self, html, parent_url, depth):
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
                self.crawl(full_url, depth + 1)

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
                self.crawl(form_url, depth + 1)

    def _parse_scripts_for_endpoints(self, html, parent_url, depth):
        if not html or depth > self.max_depth:
            return

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

        # External bundles (limit to keep scans fast)
        fetched = 0
        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if not src:
                continue
            src_url = urljoin(parent_url, src)
            if not self._should_fetch_resource(src_url):
                continue
            try:
                res = self.session.get(src_url)
            except Exception:
                res = None
            if not res or res.status_code >= 400:
                continue

            # Skip huge/non-text responses
            try:
                content_len = len(getattr(res, "content", b"") or b"")
            except Exception:
                content_len = 0
            if content_len and content_len > 1024 * 1024:
                continue
            ct = (getattr(res, "headers", {}) or {}).get("Content-Type", "").lower()
            if ct and ("javascript" not in ct and "text" not in ct and "json" not in ct):
                continue

            for candidate in self._extract_endpoint_candidates(res.text or ""):
                full_url = urljoin(parent_url, candidate)
                if self._should_visit(full_url):
                    self._add_endpoint(full_url)

            fetched += 1
            if fetched >= 5:
                break

    def _extract_endpoint_candidates(self, text: str):
        if not text:
            return []

        # Keep this conservative to avoid wild false positives.
        # Targets common backend patterns used by SPAs (Juice Shop uses /rest/* heavily).
        patterns = [
            r"(?i)\bfetch\(\s*['\"]([^'\"]+)['\"]",
            r"(?i)\baxios\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]",
            r"(?i)\bxmlhttprequest\b[\s\S]{0,200}open\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            r"['\"](/(?:api|rest|graphql|v1|v2)/[^'\"\s<>]{1,200})['\"]",
        ]

        candidates = []
        for pat in patterns:
            for match in re.findall(pat, text):
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
        if norm_url in self.visited:
            return False
        if self.same_host_only:
            host = urlparse(url).netloc
            if host and host != self.base_host:
                return False
        return True

    def _normalize_url(self, url):
        # Remove fragment, sort query params
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            q = "&".join(sorted(parsed.query.split("&")))
            return f"{base}?{q}"
        return base
