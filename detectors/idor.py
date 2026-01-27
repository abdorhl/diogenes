class IDORDetector:
    def __init__(self, identity_a, identity_b):
        self.a = identity_a
        self.b = identity_b

    def test(self, path):
        if not self.a or not self.b:
            return None
        
        try:
            res_a = self.a.get(path)
            res_b = self.b.get(path)
            
            if not res_a or not res_b:
                return None
            
            # Both get 200 but have different content = possible IDOR
            # (one user can access their data, other user can also access it)
            if res_a.status_code == 200 and res_b.status_code == 200:
                # Calculate similarity to distinguish user-specific pages from shared content
                similarity = self._text_similarity(res_a.text, res_b.text)
                length_a = len(res_a.text or "")
                length_b = len(res_b.text or "")
                length_ratio = self._length_ratio(length_a, length_b)
                
                # High similarity (80%+) on sensitive endpoints suggests IDOR
                # (user A's data visible to user B)
                if similarity > 0.8:
                    # Exclude generic public pages (sidebars, navigation, etc.)
                    if self._is_sensitive_content(res_a.text):
                        return {
                            "type": "idor",
                            "endpoint": path,
                            "evidence": f"Both {self.a.name} and {self.b.name} get identical sensitive content (similarity: {similarity:.1%})",
                            "idor_type": "horizontal_same_content",
                            "confidence": 0.8,
                            "identity_a": self.a.name,
                            "identity_b": self.b.name,
                            "status_code": 200,
                            "similarity": similarity,
                            "length_ratio": length_ratio
                        }
                
                # Moderate similarity (40-80%) might indicate shared user data
                elif 0.4 < similarity < 0.8:
                    if self._is_sensitive_content(res_a.text):
                        return {
                            "type": "idor",
                            "endpoint": path,
                            "evidence": f"Significant content overlap between {self.a.name} and {self.b.name} (similarity: {similarity:.1%})",
                            "idor_type": "horizontal_partial_overlap",
                            "confidence": 0.6,
                            "identity_a": self.a.name,
                            "identity_b": self.b.name,
                            "status_code": 200,
                            "similarity": similarity,
                            "length_ratio": length_ratio
                        }

                # Different content but similar size can still indicate unauthorized access
                if length_ratio >= 0.9 and self._is_sensitive_content(res_a.text) and self._is_sensitive_content(res_b.text):
                    return {
                        "type": "idor",
                        "endpoint": path,
                        "evidence": f"Both identities accessed sensitive content with similar size (len ratio: {length_ratio:.2f})",
                        "idor_type": "horizontal_similar_size",
                        "confidence": 0.5,
                        "identity_a": self.a.name,
                        "identity_b": self.b.name,
                        "status_code": 200,
                        "similarity": similarity,
                        "length_ratio": length_ratio
                    }

            # Vertical access-control signal: different status codes (one allowed, one denied)
            if res_a.status_code in (200, 201) and res_b.status_code in (401, 403):
                return {
                    "type": "idor",
                    "endpoint": path,
                    "evidence": f"{self.a.name} allowed but {self.b.name} denied (status {res_a.status_code}/{res_b.status_code})",
                    "idor_type": "vertical_access_control",
                    "confidence": 0.4,
                    "identity_a": self.a.name,
                    "identity_b": self.b.name,
                    "status_code": res_a.status_code
                }
            if res_b.status_code in (200, 201) and res_a.status_code in (401, 403):
                return {
                    "type": "idor",
                    "endpoint": path,
                    "evidence": f"{self.b.name} allowed but {self.a.name} denied (status {res_b.status_code}/{res_a.status_code})",
                    "idor_type": "vertical_access_control",
                    "confidence": 0.4,
                    "identity_a": self.a.name,
                    "identity_b": self.b.name,
                    "status_code": res_b.status_code
                }
            
            # One succeeds (200), other gets denied (403/401) = proper access control
            # No IDOR here
        except Exception:
            pass
        
        return None

    def _text_similarity(self, text_a, text_b):
        """Calculate similarity between two texts (0-1)"""
        if not text_a or not text_b:
            return 0.0
        
        # Remove whitespace for comparison
        a_clean = ''.join(text_a.split())
        b_clean = ''.join(text_b.split())
        
        if len(a_clean) == 0 or len(b_clean) == 0:
            return 0.0
        
        # Simple overlap-based similarity
        matches = sum(1 for i in range(min(len(a_clean), len(b_clean))) if a_clean[i] == b_clean[i])
        return matches / max(len(a_clean), len(b_clean))

    def _length_ratio(self, len_a, len_b):
        if len_a == 0 or len_b == 0:
            return 0.0
        return min(len_a, len_b) / max(len_a, len_b)

    def _is_sensitive_content(self, text):
        """Check if response looks like user-specific data (not public content)"""
        sensitive_keywords = [
            "profile", "user", "account", "settings", "preference", 
            "email", "phone", "address", "credit", "order", "invoice",
            "dashboard", "admin", "report", "data", "records", "history"
        ]

        text_lower = text.lower() if text else ""

        # Regex indicators for sensitive data
        has_email = bool(self._regex_search(text_lower, r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"))
        has_phone = bool(self._regex_search(text_lower, r"\b\+?\d{1,3}?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b"))
        has_card = bool(self._regex_search(text_lower, r"\b(?:\d[ -]*?){13,19}\b"))

        keyword_hits = sum(1 for kw in sensitive_keywords if kw in text_lower)

        # Sensitive if multiple keyword hits or any strong indicator
        return keyword_hits >= 2 or has_email or has_phone or has_card

    def _regex_search(self, text, pattern):
        try:
            import re
            return re.search(pattern, text) is not None
        except Exception:
            return False
