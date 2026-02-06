"""
Unit tests for DIOGENES security scanner.
Tests core functionality, detectors, and edge cases.
"""

import unittest
from unittest.mock import Mock, MagicMock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validators import URLValidator, ResponseValidator, normalize_url
from core.config import ScanConfig, load_config, SCAN_PROFILES
from detectors.reflection import ReflectionDetector
from detectors.csrf import CSRFDetector


class TestURLValidator(unittest.TestCase):
    """Test URL validation and SSRF protection."""
    
    def setUp(self):
        self.validator = URLValidator(block_private_ips=True)
    
    def test_valid_http_url(self):
        """Test that valid HTTP URLs pass validation."""
        self.assertTrue(self.validator.is_valid("http://example.com/path"))
        self.assertTrue(self.validator.is_valid("https://example.com/path"))
    
    def test_blocks_private_ips(self):
        """Test that private IPs are blocked."""
        private_urls = [
            "http://127.0.0.1/admin",
            "http://localhost/secret",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/admin",
            "http://172.16.0.1/internal",
        ]
        for url in private_urls:
            with self.subTest(url=url):
                self.assertFalse(self.validator.is_valid(url))
    
    def test_blocks_cloud_metadata(self):
        """Test that cloud metadata endpoints are blocked."""
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
        ]
        for url in metadata_urls:
            with self.subTest(url=url):
                self.assertFalse(self.validator.is_valid(url))
    
    def test_blocks_invalid_schemes(self):
        """Test that non-HTTP schemes are blocked."""
        invalid_schemes = [
            "file:///etc/passwd",
            "ftp://example.com/file",
            "javascript:alert(1)",
        ]
        for url in invalid_schemes:
            with self.subTest(url=url):
                self.assertFalse(self.validator.is_valid(url))
    
    def test_same_host_restriction(self):
        """Test that same-host restriction works."""
        self.assertTrue(
            self.validator.is_valid("http://example.com/path1", base_host="example.com")
        )
        self.assertFalse(
            self.validator.is_valid("http://evil.com/path", base_host="example.com")
        )


class TestResponseValidator(unittest.TestCase):
    """Test HTTP response validation."""
    
    def setUp(self):
        self.validator = ResponseValidator(max_size=1024)
    
    def test_valid_response(self):
        """Test that valid responses pass."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"Hello World"
        mock_response.history = []
        
        self.assertTrue(self.validator.is_valid(mock_response))
    
    def test_rejects_large_responses(self):
        """Test that oversized responses are rejected."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"x" * 2000  # Larger than max_size
        mock_response.history = []
        
        self.assertFalse(self.validator.is_valid(mock_response))
    
    def test_rejects_server_errors(self):
        """Test that 5xx responses are rejected."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.content = b"Error"
        
        self.assertFalse(self.validator.is_valid(mock_response))
    
    def test_detects_redirect_loops(self):
        """Test that excessive redirects are detected."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.history = [Mock()] * 10  # Too many redirects
        
        self.assertFalse(self.validator.is_valid(mock_response))


class TestURLNormalization(unittest.TestCase):
    """Test URL normalization."""
    
    def test_normalize_removes_fragment(self):
        """Test that fragments are removed."""
        url = "http://example.com/path#fragment"
        normalized = normalize_url(url)
        self.assertNotIn("#", normalized)
    
    def test_normalize_sorts_params(self):
        """Test that query params are sorted."""
        url1 = "http://example.com/path?b=2&a=1"
        url2 = "http://example.com/path?a=1&b=2"
        
        self.assertEqual(normalize_url(url1), normalize_url(url2))
    
    def test_normalize_lowercases_host(self):
        """Test that host is lowercased."""
        url = "http://Example.COM/Path"
        normalized = normalize_url(url)
        self.assertIn("example.com", normalized)


class TestScanConfig(unittest.TestCase):
    """Test configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ScanConfig()
        self.assertEqual(config.timeout, 10)
        self.assertEqual(config.max_depth, 3)
        self.assertTrue(config.enable_concurrent)
    
    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        config = ScanConfig.from_dict({
            "timeout": 20,
            "max_depth": 5,
        })
        self.assertEqual(config.timeout, 20)
        self.assertEqual(config.max_depth, 5)
    
    def test_scan_profiles(self):
        """Test predefined scan profiles."""
        self.assertIn("stealth", SCAN_PROFILES)
        self.assertIn("aggressive", SCAN_PROFILES)
        
        stealth = SCAN_PROFILES["stealth"]
        self.assertGreater(stealth.delay, 0)
        self.assertTrue(stealth.rotate_user_agents)


class TestReflectionDetector(unittest.TestCase):
    """Test reflection detector."""
    
    def setUp(self):
        self.mock_client = Mock()
        self.detector = ReflectionDetector(self.mock_client)
    
    def test_detects_reflection(self):
        """Test that reflected input is detected."""
        mock_response = Mock()
        mock_response.text = "Hello bp_abc123 World"
        self.mock_client.get.return_value = mock_response
        
        # Patch uuid to return predictable value
        with patch('detectors.reflection.uuid.uuid4') as mock_uuid:
            mock_uuid.return_value.hex = 'abc123000000'
            result = self.detector.test("/path", "q")
        
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "reflection")
        self.assertEqual(result["param"], "q")
    
    def test_no_false_positive(self):
        """Test that non-reflected input doesn't trigger."""
        mock_response = Mock()
        mock_response.text = "No marker here"
        self.mock_client.get.return_value = mock_response
        
        result = self.detector.test("/path", "q")
        self.assertIsNone(result)
    
    def test_handles_none_response(self):
        """Test graceful handling of None response."""
        self.mock_client.get.return_value = None
        result = self.detector.test("/path", "q")
        self.assertIsNone(result)


class TestCSRFDetector(unittest.TestCase):
    """Test CSRF detector."""
    
    def setUp(self):
        self.mock_client = Mock()
        self.detector = CSRFDetector(self.mock_client)
    
    def test_detects_form_without_token(self):
        """Test detection of forms without CSRF tokens."""
        html = '<form action="/submit"><input name="username"></form>'
        mock_response = Mock()
        mock_response.text = html
        self.mock_client.get.return_value = mock_response
        
        result = self.detector.test("/form")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "csrf")
    
    def test_accepts_form_with_token(self):
        """Test that forms with CSRF tokens don't trigger."""
        html = '<form action="/submit"><input name="csrf_token" value="abc"><input name="username"></form>'
        mock_response = Mock()
        mock_response.text = html
        self.mock_client.get.return_value = mock_response
        
        result = self.detector.test("/form")
        self.assertIsNone(result)
    
    def test_detects_various_token_names(self):
        """Test detection of various CSRF token naming conventions."""
        token_names = ["csrf", "csrf_token", "csrfToken", "_csrf", "authenticity_token"]
        
        for token_name in token_names:
            with self.subTest(token_name=token_name):
                html = f'<form><input name="{token_name}"></form>'
                mock_response = Mock()
                mock_response.text = html
                self.mock_client.get.return_value = mock_response
                
                result = self.detector.test("/form")
                # Should not trigger (form has CSRF protection)
                self.assertIsNone(result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def test_empty_url_handling(self):
        """Test handling of empty URLs."""
        validator = URLValidator()
        self.assertFalse(validator.is_valid(""))
        self.assertFalse(validator.is_valid(None))
    
    def test_malformed_url_handling(self):
        """Test handling of malformed URLs."""
        validator = URLValidator()
        malformed_urls = [
            "not a url",
            "http://",
            "://example.com",
            "http://exam ple.com",
        ]
        for url in malformed_urls:
            with self.subTest(url=url):
                result = validator.is_valid(url)
                # Should return False without crashing
                self.assertIsInstance(result, bool)
    
    def test_unicode_handling(self):
        """Test handling of Unicode in URLs and payloads."""
        validator = URLValidator()
        unicode_url = "http://example.com/路径"
        # Should not crash
        result = validator.is_valid(unicode_url)
        self.assertIsInstance(result, bool)


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
