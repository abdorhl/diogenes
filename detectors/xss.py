import html
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urlparse

# Some targets return XML (e.g., sitemap/feeds). We still parse as HTML for
# best-effort script discovery; suppress noisy BS4 warnings.
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class XSSDetector:
    PAYLOADS = [
        '<svg/onload=alert(1)>',
        '"/><img src=x onerror=alert(2)>',
        "'><script>alert(3)</script>",
        "<img src=x onerror=alert(4)>",
        "</textarea><svg/onload=alert(5)>",
        "</script><svg/onload=alert(6)>",
        "<details open ontoggle=alert(7)>",
        "javascript:alert(8)",
        "onmouseover=alert(9)",
        "</style><svg/onload=alert(10)>"
    ]
    
    # Common parameter names in web apps
    COMMON_PARAMS = ["q", "search", "id", "input", "txtInput", "keyword", "query", "name", "msg", "comment", "text", "search_term", "url", "username"]

    def __init__(self, client):
        self.client = client

    def test(self, path, param=None):
        # If no specific param given, try common ones
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        for test_param in params_to_test:
            # PRIORITY: Test payload reflection first (higher confidence findings)
            for payload in self.PAYLOADS:
                try:
                    res = self.client.get(path, params={test_param: payload})
                    if not res:
                        continue
                    
                    response_text = res.text
                    
                    # Check if payload is reflected unescaped in response
                    if payload in response_text:
                        context = self._context(BeautifulSoup(response_text, "html.parser"), response_text, payload)

                        # Check if payload persists without the parameter (stored signal)
                        try:
                            res_plain = self.client.get(path)
                            if res_plain and payload in (res_plain.text or ""):
                                return {
                                    "type": "xss",
                                    "endpoint": path,
                                    "param": test_param,
                                    "payload": payload,
                                    "context": context,
                                    "evidence": "Payload persisted without parameter (stored XSS signal)",
                                    "xss_type": "stored",
                                    "confidence": 0.8
                                }
                        except Exception:
                            pass

                        return {
                            "type": "xss",
                            "endpoint": path,
                            "param": test_param,
                            "payload": payload,
                            "context": context,
                            "evidence": "Payload reflected in response (reflected XSS signal)",
                            "xss_type": "reflected",
                            "confidence": 0.9 if context != "unknown" else 0.7
                        }
                    
                    # Also check for HTML-encoded versions (still exploitable)
                    encoded_payload = html.escape(payload)
                    if encoded_payload in response_text:
                        # Lower confidence for HTML-encoded, but still worth reporting
                        return {
                            "type": "xss",
                            "endpoint": path,
                            "param": test_param,
                            "payload": payload,
                            "evidence": "Payload reflected (HTML-encoded)",
                            "context": "html_encoded",
                            "xss_type": "reflected",
                            "confidence": 0.6
                        }
                except Exception:
                    pass
            
            # FALLBACK: Check for DOM-based XSS signals if no payload reflection found
            try:
                res_probe = self.client.get(path, params={test_param: "diogenes_probe"})
                if res_probe and getattr(res_probe, "text", ""):
                    dom_signal = self._detect_dom_xss_signal(res_probe.text, test_param)
                    if dom_signal:
                        suggested = self.PAYLOADS[0]
                        return {
                            "type": "xss",
                            "endpoint": path,
                            "param": test_param,
                            "payload": f"Suggested manual test: ?{test_param}={suggested}",
                            "evidence": dom_signal + " (no server-side reflection observed)",
                            "context": "dom",
                            "xss_type": "dom",
                            "confidence": 0.6
                        }
            except Exception:
                pass
        
        return None

    def _context(self, soup, raw_text, payload):
        # Check if payload is in text
        if payload in soup.get_text():
            return "html_text"

        # Check if payload is in HTML attributes (with attribute name)
        for tag in soup.find_all():
            for attr_name, attr_value in tag.attrs.items():
                if isinstance(attr_value, str) and payload in attr_value:
                    return f"html_attribute:{attr_name}"

        # Check if payload appears inside script or style blocks
        if self._in_tag(raw_text, payload, "script"):
            return "script"
        if self._in_tag(raw_text, payload, "style"):
            return "style"

        # Check for JSON context
        if f'"{payload}"' in raw_text or f"'{payload}'" in raw_text:
            return "json_string"

        return "unknown"

    def _in_tag(self, raw_text, payload, tag):
        lower = raw_text.lower()
        start_tag = f"<{tag}"
        end_tag = f"</{tag}>"
        start = 0
        while True:
            idx = lower.find(start_tag, start)
            if idx == -1:
                return False
            end = lower.find(end_tag, idx)
            if end == -1:
                return False
            block = raw_text[idx:end]
            if payload in block:
                return True
            start = end + len(end_tag)

    def _detect_dom_xss_signal(self, raw_text, param):
        try:
            soup = BeautifulSoup(raw_text or "", "html.parser")
            scripts = soup.find_all("script")

            sinks = [
                "innerhtml", "outerhtml", "insertadjacenthtml", "document.write",
                "document.writeln", "eval(", "settimeout(", "setinterval(",
                "function(", "location=", "location.href", "srcdoc",
                "setattribute(", "jquery.html(", "$.html(", ".html("
            ]
            sources = [
                "location", "document.url", "document.location", "location.hash",
                "location.search", "location.href", "document.referrer",
                "localstorage", "sessionstorage", "window.location"
            ]

            # 1) Inline scripts
            for script in scripts:
                js = (script.string or script.get_text() or "")
                signal = self._dom_signal_from_js(js, sinks, sources, param)
                if signal:
                    return signal

            # 2) External bundles referenced by the page (common for SPAs)
            external_sources = []
            for script in soup.find_all("script", src=True):
                src = script.get("src")
                if not src:
                    continue
                external_sources.append(src)

            # Scan a limited number of bundles to keep scans fast.
            scanned = 0
            for src in external_sources[:5]:
                try:
                    # Best-effort resolve relative URLs.
                    base = getattr(self.client, "base_url", "") or ""
                    src_url = urljoin(base + "/", src) if base else src

                    # Same-host only.
                    if src_url.startswith(("http://", "https://")):
                        if urlparse(src_url).netloc and urlparse(src_url).netloc != urlparse(base).netloc:
                            continue

                    res = self.client.get(src_url)
                    if not res or getattr(res, "status_code", 0) >= 400:
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

                    signal = self._dom_signal_from_js(res.text or "", sinks, sources, param)
                    if signal:
                        return signal + " (external JS bundle)"

                    scanned += 1
                except Exception:
                    continue
        except Exception:
            return ""

        return ""

    def _dom_signal_from_js(self, js_text, sinks, sources, param):
        try:
            js = (js_text or "").lower()
            if not js:
                return ""

            has_sink = any(s in js for s in sinks)
            has_source = any(s in js for s in sources)
            references_param = bool(param) and (param.lower() in js)

            if has_sink and has_source and references_param:
                return "DOM XSS signal: sink+source pattern with parameter reference"

            if has_sink and has_source:
                return "DOM XSS signal: sink+source pattern"
        except Exception:
            return ""
        return ""

