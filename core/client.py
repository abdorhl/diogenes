import requests

class HttpClient:
    def __init__(self, base_url, cookies=None, headers=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

    def get(self, path, params=None):
        return self.session.get(self.base_url + path, params=params, timeout=10)

    def post(self, path, data=None):
        return self.session.post(self.base_url + path, data=data, timeout=10)
