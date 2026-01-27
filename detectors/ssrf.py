class SSRFDetector:
    PAYLOADS = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/"]

    def __init__(self, client):
        self.client = client

    def test(self, path, param):
        for payload in self.PAYLOADS:
            try:
                res = self.client.get(path, params={param: payload})
                if not res:
                    continue
                
                # Only flag if the payload or SSRF indicators appear in unexpected places
                # (not just in the form echoed back or normal HTML)
                text_lower = res.text.lower()
                
                # Look for actual SSRF indicators (error messages, system info, etc.)
                ssrf_indicators = [
                    "root:x:", "ec2", "meta-data", "aws", "hmac", "curl:", 
                    "timeout", "connection refused", "unreachable"
                ]
                
                # Only report if we see actual SSRF behavior (not just echo)
                if any(indicator in text_lower for indicator in ssrf_indicators):
                    return {
                        "type": "ssrf",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": "Possible SSRF reflection detected",
                        "confidence": 0.7
                    }
            except Exception:
                pass
        
        return None
