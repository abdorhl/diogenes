"""
CORS Misconfiguration Detector
Detects Cross-Origin Resource Sharing security vulnerabilities
"""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CORSDetector:
    """Detect CORS misconfiguration vulnerabilities
    
    Tests for:
    1. Reflected Origin (accepts any origin)
    2. Null origin accepted
    3. Wildcard with credentials
    4. Insecure protocol (HTTP allowed on HTTPS site)
    5. Subdomain wildcard vulnerabilities
    """
    
    # Test origins (including attacker-controlled domains)
    TEST_ORIGINS = [
        "https://evil.com",
        "http://evil.com",
        "https://attacker.com",
        "null",
        "https://trusted-site.com.evil.com",  # Subdomain takeover
    ]
    
    def __init__(self, client):
        """Initialize CORS detector
        
        Args:
            client: HTTP client for making requests
        """
        self.client = client
        logger.info("CORS Detector initialized")
    
    def test(self, path):
        """Test endpoint for CORS misconfigurations
        
        Args:
            path: URL path to test
            
        Returns:
            Dictionary with finding details if vulnerability found, None otherwise
        """
        findings = []
        
        # Test 1: Reflected Origin (most critical)
        result = self._test_reflected_origin(path)
        if result:
            findings.append(result)
        
        # Test 2: Null origin accepted
        result = self._test_null_origin(path)
        if result:
            findings.append(result)
        
        # Test 3: Wildcard with credentials
        result = self._test_wildcard_credentials(path)
        if result:
            findings.append(result)
        
        # Test 4: Insecure protocol
        result = self._test_insecure_protocol(path)
        if result:
            findings.append(result)
        
        # Test 5: Subdomain wildcard
        result = self._test_subdomain_wildcard(path)
        if result:
            findings.append(result)
        
        # Return the most severe finding
        if findings:
            # Sort by confidence (highest first)
            findings.sort(key=lambda x: x.get('confidence', 0), reverse=True)
            return findings[0]
        
        return None
    
    def _test_reflected_origin(self, path):
        """Test if Origin header is reflected in ACAO"""
        for test_origin in self.TEST_ORIGINS:
            try:
                res = self.client.get(
                    path,
                    headers={'Origin': test_origin}
                )
                
                if not res:
                    continue
                
                # Check Access-Control-Allow-Origin header
                acao = res.headers.get('Access-Control-Allow-Origin', '')
                acac = res.headers.get('Access-Control-Allow-Credentials', '')
                
                # Critical: Reflected origin with credentials
                if acao == test_origin and acac.lower() == 'true':
                    return {
                        "type": "cors_misconfiguration",
                        "subtype": "reflected_origin_with_credentials",
                        "endpoint": path,
                        "evidence": f"Origin '{test_origin}' reflected with credentials=true",
                        "acao": acao,
                        "acac": acac,
                        "test_origin": test_origin,
                        "confidence": 0.95,
                        "severity": "critical",
                        "description": "CORS allows arbitrary origins with credentials - data can be stolen"
                    }
                
                # High: Reflected origin without credentials
                elif acao == test_origin:
                    return {
                        "type": "cors_misconfiguration",
                        "subtype": "reflected_origin",
                        "endpoint": path,
                        "evidence": f"Origin '{test_origin}' reflected (no credentials)",
                        "acao": acao,
                        "test_origin": test_origin,
                        "confidence": 0.8,
                        "severity": "high",
                        "description": "CORS reflects arbitrary origins - potential data leakage"
                    }
            
            except Exception as e:
                logger.debug(f"Reflected origin test error: {e}")
                continue
        
        return None
    
    def _test_null_origin(self, path):
        """Test if null origin is accepted"""
        try:
            res = self.client.get(
                path,
                headers={'Origin': 'null'}
            )
            
            if not res:
                return None
            
            acao = res.headers.get('Access-Control-Allow-Origin', '')
            acac = res.headers.get('Access-Control-Allow-Credentials', '')
            
            # Null origin accepted with credentials
            if acao == 'null' and acac.lower() == 'true':
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "null_origin_with_credentials",
                    "endpoint": path,
                    "evidence": "Origin 'null' accepted with credentials=true",
                    "acao": acao,
                    "acac": acac,
                    "confidence": 0.9,
                    "severity": "critical",
                    "description": "CORS accepts null origin with credentials - exploitable via sandboxed iframe"
                }
            
            # Null origin accepted
            elif acao == 'null':
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "null_origin",
                    "endpoint": path,
                    "evidence": "Origin 'null' accepted",
                    "acao": acao,
                    "confidence": 0.75,
                    "severity": "high",
                    "description": "CORS accepts null origin - exploitable via sandboxed iframe"
                }
        
        except Exception as e:
            logger.debug(f"Null origin test error: {e}")
        
        return None
    
    def _test_wildcard_credentials(self, path):
        """Test for wildcard origin with credentials"""
        try:
            res = self.client.get(path)
            
            if not res:
                return None
            
            acao = res.headers.get('Access-Control-Allow-Origin', '')
            acac = res.headers.get('Access-Control-Allow-Credentials', '')
            
            # Wildcard with credentials (technically invalid, but some browsers allowed it)
            if acao == '*' and acac.lower() == 'true':
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "wildcard_with_credentials",
                    "endpoint": path,
                    "evidence": "ACAO=* with credentials=true",
                    "acao": acao,
                    "acac": acac,
                    "confidence": 0.85,
                    "severity": "high",
                    "description": "Invalid CORS config: wildcard with credentials (browsers may reject)"
                }
            
            # Just wildcard (lower severity)
            elif acao == '*':
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "wildcard_origin",
                    "endpoint": path,
                    "evidence": "ACAO=* allows all origins",
                    "acao": acao,
                    "confidence": 0.6,
                    "severity": "medium",
                    "description": "CORS allows all origins - data accessible to any website"
                }
        
        except Exception as e:
            logger.debug(f"Wildcard test error: {e}")
        
        return None
    
    def _test_insecure_protocol(self, path):
        """Test if HTTP origins are allowed on HTTPS endpoint"""
        parsed = urlparse(self.client.base_url)
        
        # Only test if target is HTTPS
        if parsed.scheme != 'https':
            return None
        
        try:
            http_origin = f"http://{parsed.netloc}"
            
            res = self.client.get(
                path,
                headers={'Origin': http_origin}
            )
            
            if not res:
                return None
            
            acao = res.headers.get('Access-Control-Allow-Origin', '')
            acac = res.headers.get('Access-Control-Allow-Credentials', '')
            
            # HTTP origin accepted on HTTPS endpoint with credentials
            if acao == http_origin and acac.lower() == 'true':
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "insecure_protocol_with_credentials",
                    "endpoint": path,
                    "evidence": f"HTTP origin '{http_origin}' accepted on HTTPS endpoint with credentials",
                    "acao": acao,
                    "acac": acac,
                    "confidence": 0.85,
                    "severity": "high",
                    "description": "CORS allows HTTP origins on HTTPS - vulnerable to MITM"
                }
            
            # HTTP origin accepted
            elif acao == http_origin:
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "insecure_protocol",
                    "endpoint": path,
                    "evidence": f"HTTP origin '{http_origin}' accepted on HTTPS endpoint",
                    "acao": acao,
                    "confidence": 0.7,
                    "severity": "medium",
                    "description": "CORS allows HTTP origins on HTTPS - potential MITM"
                }
        
        except Exception as e:
            logger.debug(f"Insecure protocol test error: {e}")
        
        return None
    
    def _test_subdomain_wildcard(self, path):
        """Test if subdomain matching is too permissive"""
        parsed = urlparse(self.client.base_url)
        base_domain = parsed.netloc.split(':')[0]
        
        # Test with evil subdomain
        evil_origin = f"https://evil.{base_domain}"
        
        try:
            res = self.client.get(
                path,
                headers={'Origin': evil_origin}
            )
            
            if not res:
                return None
            
            acao = res.headers.get('Access-Control-Allow-Origin', '')
            acac = res.headers.get('Access-Control-Allow-Credentials', '')
            
            # Evil subdomain accepted with credentials
            if acao == evil_origin and acac.lower() == 'true':
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "subdomain_wildcard_with_credentials",
                    "endpoint": path,
                    "evidence": f"Subdomain '{evil_origin}' accepted with credentials",
                    "acao": acao,
                    "acac": acac,
                    "confidence": 0.8,
                    "severity": "high",
                    "description": "CORS accepts any subdomain with credentials - vulnerable to subdomain takeover"
                }
            
            # Evil subdomain accepted
            elif acao == evil_origin:
                return {
                    "type": "cors_misconfiguration",
                    "subtype": "subdomain_wildcard",
                    "endpoint": path,
                    "evidence": f"Subdomain '{evil_origin}' accepted",
                    "acao": acao,
                    "confidence": 0.65,
                    "severity": "medium",
                    "description": "CORS accepts any subdomain - vulnerable to subdomain takeover"
                }
        
        except Exception as e:
            logger.debug(f"Subdomain test error: {e}")
        
        return None
