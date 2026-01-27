from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class Finding:
    """Represents a security observation."""
    type: str  # xss, sqli, csrf, ssrf, idor, reflection
    endpoint: str
    confidence: float  # 0.0 to 1.0
    evidence: str
    param: Optional[str] = None
    payload: Optional[str] = None
    context: Optional[str] = None
    status_code: Optional[int] = None
    identity_a: Optional[str] = None
    identity_b: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "endpoint": self.endpoint,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "param": self.param,
            "payload": self.payload,
            "context": self.context,
            "status_code": self.status_code,
            "identity_a": self.identity_a,
            "identity_b": self.identity_b,
        }
