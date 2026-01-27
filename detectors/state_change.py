class StateChangeDetector:
    STATE_METHODS = ["POST", "PUT", "DELETE", "PATCH"]

    def analyze(self, endpoint):
        if "form" not in endpoint:
            return None

        protections = {
            "csrf_token": "csrf" in endpoint.lower(),
            "origin_check": False
        }

        return {
            "type": "state_change",
            "endpoint": endpoint,
            "protections": protections,
            "confidence": 0.7 if not any(protections.values()) else 0.4
        }
