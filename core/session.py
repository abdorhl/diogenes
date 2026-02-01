import requests
import time
from typing import Optional, Dict
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class Session:
    """Manages HTTP session, cookies, and headers for an identity."""
    
    def __init__(self, name: str, base_url: str, cookies: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, delay: float = 0.0, pool_size: int = 20):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.delay = delay  # Delay between requests in seconds
        self.last_request_time = 0.0
        
        # Configure connection pooling for concurrent requests
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=Retry(total=2, backoff_factor=0.1)
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
    
    def get(self, path: str, params: Optional[Dict] = None, timeout: int = 10):
        try:
            # Rate limiting: Wait if needed
            if self.delay > 0:
                elapsed = time.time() - self.last_request_time
                if elapsed < self.delay:
                    time.sleep(self.delay - elapsed)
            
            # Handle full URLs vs paths
            if path.startswith("http://") or path.startswith("https://"):
                url = path
            else:
                # Remove leading slash to avoid double slashes
                if path.startswith("/"):
                    url = self.base_url + path
                else:
                    url = self.base_url + "/" + path
            
            # If we were given a full URL (or a URL that already has a query string),
            # merge params into the URL to avoid duplicate keys.
            if params:
                url = self._merge_query_params(url, params)
                params = None

            self.last_request_time = time.time()
            return self.session.get(url, params=params, timeout=timeout, allow_redirects=True)
        except Exception as e:
            return None
    
    def post(self, path: str, data: Optional[Dict] = None, timeout: int = 10):
        try:
            # Rate limiting: Wait if needed
            if self.delay > 0:
                elapsed = time.time() - self.last_request_time
                if elapsed < self.delay:
                    time.sleep(self.delay - elapsed)
            
            # Handle full URLs vs paths
            if path.startswith("http://") or path.startswith("https://"):
                url = path
            else:
                if path.startswith("/"):
                    url = self.base_url + path
                else:
                    url = self.base_url + "/" + path
            
            self.last_request_time = time.time()
            return self.session.post(url, data=data, timeout=timeout, allow_redirects=True)
        except Exception as e:
            return None

    def _merge_query_params(self, url: str, params: Dict) -> str:
        try:
            split = urlsplit(url)
            existing = dict(parse_qsl(split.query, keep_blank_values=True))
            for k, v in (params or {}).items():
                existing[str(k)] = "" if v is None else str(v)
            new_query = urlencode(existing, doseq=True)
            return urlunsplit((split.scheme, split.netloc, split.path, new_query, split.fragment))
        except Exception:
            return url
