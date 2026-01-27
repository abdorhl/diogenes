import uuid
from bs4 import BeautifulSoup

class ReflectionDetector:
    def __init__(self, client):
        self.client = client

    def test(self, path, param):
        marker = f"bp_{uuid.uuid4().hex[:6]}"
        res = self.client.get(path, params={param: marker})

        if not res or not getattr(res, "text", ""):
            return None

        if marker not in res.text:
            return None

        return {
            "type": "reflection",
            "endpoint": path,
            "param": param,
            "context": self._context(res.text, marker),
            "confidence": 0.6
        }

    def _context(self, html, marker):
        soup = BeautifulSoup(html, "html.parser")

        if marker in soup.get_text():
            return "html_text"

        for tag in soup.find_all():
            for attr in tag.attrs.values():
                if isinstance(attr, str) and marker in attr:
                    return "html_attribute"

        return "unknown"
