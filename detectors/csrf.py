"""CSRF (Cross-Site Request Forgery) Detector
Detects CSRF vulnerabilities with token validation and advanced testing
"""

from bs4 import BeautifulSoup
import logging
import re

logger = logging.getLogger(__name__)


class CSRFDetector:
    """Detect CSRF vulnerabilities with comprehensive testing
    
    Tests for:
    1. Missing CSRF tokens in forms
    2. Token validation (accepts requests without token)
    3. Token strength analysis
    4. HTTP method verification
    """
    
    # Common CSRF token naming conventions
    TOKEN_PATTERNS = ['csrf', '_csrf', 'authenticity', 'token', 'xsrf', 'nonce', 'state']
    
    def __init__(self, client):
        """Initialize CSRF detector
        
        Args:
            client: HTTP client for making requests
        """
        self.client = client
        logger.info("CSRF Detector initialized")

    def test(self, path):
        """Test endpoint for CSRF vulnerabilities
        
        Args:
            path: URL path to test
            
        Returns:
            Dictionary with finding details if vulnerability found, None otherwise
        """
        try:
            res = self.client.get(path)
            if not res or not res.text:
                return None
            
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")
            
            if not forms:
                return None
            
            for form in forms:
                # Test 1: Check if form has CSRF token
                csrf_token_input = self._find_csrf_token(form)
                
                if not csrf_token_input:
                    # Form without token - most basic CSRF
                    form_action = form.get('action', path)
                    form_method = form.get('method', 'get').upper()
                    
                    # Only report for state-changing methods
                    if form_method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                        return {
                            "type": "csrf",
                            "subtype": "missing_token",
                            "endpoint": path,
                            "form_action": form_action,
                            "form_method": form_method,
                            "evidence": f"{form_method} form without CSRF token",
                            "confidence": 0.8,
                            "severity": "medium",
                            "description": "Form lacks CSRF protection"
                        }
                else:
                    # Form has token - test if it's validated
                    result = self._test_token_validation(path, form, csrf_token_input)
                    if result:
                        return result
                    
                    # Test token strength
                    result = self._test_token_strength(csrf_token_input)
                    if result:
                        result["endpoint"] = path
                        return result
        
        except Exception as e:
            logger.debug(f"CSRF test error: {e}")
        
        return None
    
    def _find_csrf_token(self, form):
        """Find CSRF token input in form"""
        for inp in form.find_all('input'):
            name = (inp.get('name', '') + inp.get('id', '')).lower()
            if any(pattern in name for pattern in self.TOKEN_PATTERNS):
                return inp
        return None
    
    def _test_token_validation(self, path, form, csrf_input):
        """Test if CSRF token is actually validated server-side"""
        try:
            form_action = form.get('action', path)
            if form_action.startswith('/'):
                form_action = self.client.base_url + form_action
            elif not form_action.startswith('http'):
                # Relative URL
                from urllib.parse import urljoin
                form_action = urljoin(self.client.base_url, form_action)
            
            form_method = form.get('method', 'post').lower()
            
            # Extract form data
            form_data = {}
            for inp in form.find_all('input'):
                name = inp.get('name', '')
                value = inp.get('value', '')
                if name:
                    form_data[name] = value
            
            # Test 1: Remove CSRF token completely
            csrf_name = csrf_input.get('name', '')
            if csrf_name and csrf_name in form_data:
                test_data = form_data.copy()
                del test_data[csrf_name]
                
                if form_method == 'post':
                    res_no_token = self.client.post(form_action, data=test_data)
                else:
                    res_no_token = self.client.request(form_method.upper(), form_action, data=test_data)
                
                # If request succeeds without token, CSRF protection is broken
                if res_no_token and res_no_token.status_code in [200, 201, 302, 303]:
                    return {
                        "type": "csrf",
                        "subtype": "token_not_validated",
                        "endpoint": path,
                        "form_action": form_action,
                        "evidence": "Form submitted successfully without CSRF token",
                        "confidence": 0.95,
                        "severity": "high",
                        "description": "CSRF token is present but not validated server-side"
                    }
            
            # Test 2: Use invalid/static token
            if csrf_name:
                test_data = form_data.copy()
                test_data[csrf_name] = "invalid_token_12345"
                
                if form_method == 'post':
                    res_invalid = self.client.post(form_action, data=test_data)
                else:
                    res_invalid = self.client.request(form_method.upper(), form_action, data=test_data)
                
                # If invalid token is accepted, CSRF protection is broken
                if res_invalid and res_invalid.status_code in [200, 201, 302, 303]:
                    return {
                        "type": "csrf",
                        "subtype": "token_not_validated",
                        "endpoint": path,
                        "form_action": form_action,
                        "evidence": "Form accepted invalid CSRF token",
                        "confidence": 0.9,
                        "severity": "high",
                        "description": "CSRF token validation is weak or non-existent"
                    }
        
        except Exception as e:
            logger.debug(f"Token validation test error: {e}")
        
        return None
    
    def _test_token_strength(self, csrf_input):
        """Test if CSRF token is strong enough"""
        token_value = csrf_input.get('value', '')
        
        if not token_value:
            return None
        
        # Test 1: Token too short (weak)
        if len(token_value) < 16:
            return {
                "type": "csrf",
                "subtype": "weak_token",
                "evidence": f"CSRF token too short ({len(token_value)} chars)",
                "token_length": len(token_value),
                "confidence": 0.7,
                "severity": "medium",
                "description": "CSRF token may be predictable (too short)"
            }
        
        # Test 2: Token appears to be predictable (sequential, timestamp, etc.)
        if token_value.isdigit():
            return {
                "type": "csrf",
                "subtype": "weak_token",
                "evidence": "CSRF token is purely numeric (predictable)",
                "token_sample": token_value[:20],
                "confidence": 0.85,
                "severity": "high",
                "description": "CSRF token uses weak generation (predictable)"
            }
        
        # Test 3: Token looks like a timestamp
        if re.match(r'^\d{10,13}$', token_value):
            return {
                "type": "csrf",
                "subtype": "weak_token",
                "evidence": "CSRF token appears to be a timestamp",
                "token_sample": token_value,
                "confidence": 0.8,
                "severity": "high",
                "description": "CSRF token uses timestamp (predictable)"
            }
        
        # Test 4: Check entropy (very basic)
        unique_chars = len(set(token_value))
        if unique_chars < 10 and len(token_value) > 20:
            return {
                "type": "csrf",
                "subtype": "weak_token",
                "evidence": f"CSRF token has low entropy ({unique_chars} unique chars)",
                "unique_chars": unique_chars,
                "confidence": 0.6,
                "severity": "medium",
                "description": "CSRF token may have insufficient randomness"
            }
        
        return None
