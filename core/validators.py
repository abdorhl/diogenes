"""
Security utilities and input validation for DIOGENES scanner.
Protects against SSRF, XXE, and other security issues in the scanner itself.
"""

import re
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Optional, List, Set
import logging

logger = logging.getLogger(__name__)


# Private IP ranges to block for SSRF protection
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

# Cloud metadata endpoints to block
CLOUD_METADATA_ENDPOINTS = [
    '169.254.169.254',  # AWS, Azure, GCP
    'metadata.google.internal',
    '100.100.100.200',  # Alibaba Cloud
]


class URLValidator:
    """Validates and sanitizes URLs to prevent SSRF and other attacks."""
    
    def __init__(
        self,
        allowed_schemes: List[str] = None,
        block_private_ips: bool = True,
        allowed_hosts: Optional[Set[str]] = None
    ):
        self.allowed_schemes = allowed_schemes or ['http', 'https']
        self.block_private_ips = block_private_ips
        self.allowed_hosts = allowed_hosts  # If set, only allow these hosts
    
    def is_valid(self, url: str, base_host: Optional[str] = None) -> bool:
        """
        Check if URL is valid and safe to request.
        
        Args:
            url: URL to validate
            base_host: If provided, only allow same-host URLs
        
        Returns:
            True if URL is safe to request
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in self.allowed_schemes:
                logger.debug(f"Blocked URL with invalid scheme: {parsed.scheme}")
                return False
            
            # Check if URL has a host
            if not parsed.netloc:
                logger.debug(f"Blocked URL without netloc: {url}")
                return False
            
            # Check against allowed hosts
            if self.allowed_hosts and parsed.netloc not in self.allowed_hosts:
                logger.debug(f"Blocked URL with unauthorized host: {parsed.netloc}")
                return False
            
            # Check against base host if provided
            if base_host and parsed.netloc != base_host:
                logger.debug(f"Blocked URL with different host: {parsed.netloc} != {base_host}")
                return False
            
            # Check for SSRF attempts
            if self.block_private_ips:
                if self._is_private_or_internal(parsed.netloc):
                    logger.warning(f"⚠️  Blocked potential SSRF attempt to private/internal IP: {url}")
                    return False
            
            return True
            
        except Exception as e:
            logger.debug(f"URL validation failed for {url}: {e}")
            return False
    
    def _is_private_or_internal(self, host: str) -> bool:
        """Check if host is a private IP or cloud metadata endpoint."""
        # Check cloud metadata endpoints
        for metadata_host in CLOUD_METADATA_ENDPOINTS:
            if metadata_host in host.lower():
                return True
        
        # Try to resolve as IP
        try:
            # Handle port in host
            host_without_port = host.split(':')[0]
            
            # Try to parse as IP
            ip = ipaddress.ip_address(host_without_port)
            
            # Check against private ranges
            for private_range in PRIVATE_IP_RANGES:
                if ip in private_range:
                    return True
            
            return False
            
        except ValueError:
            # Not an IP address, might be a hostname
            # Check for localhost variants
            localhost_patterns = [
                'localhost', '127.0.0.1', '::1', '0.0.0.0',
                'local', 'internal', 'intranet'
            ]
            host_lower = host.lower()
            for pattern in localhost_patterns:
                if pattern in host_lower:
                    return True
            
            return False
    
    def sanitize_url(self, url: str) -> str:
        """Remove dangerous URL components."""
        parsed = urlparse(url)
        # Remove fragments and credentials
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{'?' + parsed.query if parsed.query else ''}"


class ResponseValidator:
    """Validates HTTP responses to prevent processing malicious content."""
    
    def __init__(
        self,
        max_size: int = 2 * 1024 * 1024,  # 2MB
        max_redirects: int = 5,
        allowed_content_types: Optional[List[str]] = None
    ):
        self.max_size = max_size
        self.max_redirects = max_redirects
        self.allowed_content_types = allowed_content_types
    
    def is_valid(self, response, check_content_type: bool = False) -> bool:
        """
        Check if response is safe to process.
        
        Args:
            response: requests.Response object
            check_content_type: If True, validate content type
        
        Returns:
            True if response is safe to process
        """
        if response is None:
            return False
        
        try:
            # Check status code
            if response.status_code >= 500:
                logger.debug(f"Skipping response with server error: {response.status_code}")
                return False
            
            # Check content length
            content_length = len(response.content or b"")
            if content_length > self.max_size:
                logger.warning(f"Response too large ({content_length} bytes), skipping")
                return False
            
            # Check content type if requested
            if check_content_type and self.allowed_content_types:
                content_type = response.headers.get('Content-Type', '').lower()
                if not any(allowed in content_type for allowed in self.allowed_content_types):
                    logger.debug(f"Blocked response with invalid content type: {content_type}")
                    return False
            
            # Check for redirect loops
            if hasattr(response, 'history') and len(response.history) > self.max_redirects:
                logger.warning(f"Too many redirects ({len(response.history)}), skipping")
                return False
            
            return True
            
        except Exception as e:
            logger.debug(f"Response validation error: {e}")
            return False
    
    def extract_safe_text(self, response) -> Optional[str]:
        """Safely extract text from response with encoding handling."""
        try:
            if response is None:
                return None
            
            # Check response validity first
            if not self.is_valid(response):
                return None
            
            # Try to get text with proper encoding
            try:
                return response.text
            except UnicodeDecodeError:
                # Fallback to binary with error handling
                return response.content.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Failed to extract response text: {e}")
            return None


class PayloadValidator:
    """Validates payloads to prevent scanner from causing harm."""
    
    # Dangerous patterns that should never be in payloads
    DANGEROUS_PATTERNS = [
        r'rm\s+-rf',
        r'format\s+[c-z]:',
        r'del\s+/[fsq]',
        r'drop\s+database',
        r'truncate\s+table',
        r'shutdown',
        r'reboot',
    ]
    
    @classmethod
    def is_safe_payload(cls, payload: str) -> bool:
        """Check if payload is safe to send (doesn't contain destructive commands)."""
        payload_lower = payload.lower()
        
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                logger.error(f"⚠️  BLOCKED DANGEROUS PAYLOAD: {payload}")
                return False
        
        return True


def normalize_url(url: str) -> str:
    """
    Normalize URL for comparison and deduplication.
    
    - Removes fragment
    - Sorts query parameters
    - Lowercases scheme and host
    """
    try:
        parsed = urlparse(url)
        
        # Normalize scheme and netloc
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        
        # Sort query parameters
        if parsed.query:
            params = sorted(parsed.query.split('&'))
            query = '&'.join(params)
        else:
            query = ''
        
        # Rebuild URL without fragment
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        
        return normalized
    except Exception:
        return url


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin (scheme + host + port)."""
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        
        return (
            parsed1.scheme == parsed2.scheme and
            parsed1.netloc == parsed2.netloc
        )
    except Exception:
        return False


def safe_urljoin(base: str, url: str, validator: Optional[URLValidator] = None) -> Optional[str]:
    """
    Safely join URLs with validation.
    
    Args:
        base: Base URL
        url: URL to join
        validator: Optional URLValidator instance
    
    Returns:
        Joined URL if valid, None otherwise
    """
    try:
        joined = urljoin(base, url)
        
        if validator:
            base_host = extract_domain(base)
            if not validator.is_valid(joined, base_host=base_host):
                return None
        
        return joined
    except Exception as e:
        logger.debug(f"URL join failed for {base} + {url}: {e}")
        return None


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    # Remove path separators and dangerous characters
    dangerous_chars = ['/', '\\', '..', '\x00', ':', '*', '?', '"', '<', '>', '|']
    sanitized = filename
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '_')
    
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    
    return sanitized or 'unnamed'


def get_file_extension(url: str) -> Optional[str]:
    """Extract file extension from URL."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if '.' in path:
            return path.rsplit('.', 1)[-1]
        return None
    except Exception:
        return None


def should_skip_url(url: str, blocked_extensions: List[str]) -> bool:
    """Check if URL should be skipped based on extension."""
    ext = get_file_extension(url)
    if ext and f".{ext}" in blocked_extensions:
        return True
    return False
