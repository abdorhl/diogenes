from bs4 import BeautifulSoup

class CSRFDetector:
    def __init__(self, client):
        self.client = client

    def test(self, path):
        res = self.client.get(path)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            has_token = any('csrf' in (inp.get('name','')+inp.get('id','')).lower() for inp in form.find_all('input'))
            if not has_token:
                return {
                    "type": "csrf",
                    "endpoint": path,
                    "evidence": "Form without CSRF token detected",
                    "confidence": 0.8
                }
        return None
