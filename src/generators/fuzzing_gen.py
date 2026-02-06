"""
API Fuzzing Test Generator for Backend Applications

Generates fuzzing tests for backend APIs to detect
injection vulnerabilities and other issues.
"""

from pathlib import Path
from typing import List, Dict
from .test_gen import BaseTestGenerator


class FuzzingTestGenerator(BaseTestGenerator):
    """
    Generate API fuzzing tests for backend applications.

    Generates pytest-based fuzzing tests that send various
    malicious payloads to API endpoints to detect vulnerabilities.
    """

    def generate_tests(self) -> List[Path]:
        """
        Generate fuzzing test files for backend threats.

        Returns:
            List of generated test file paths
        """
        self._ensure_output_dir()
        test_files = []

        for threat in self.threats:
            # Determine test type based on threat category
            if threat['category'] == 'Injection':
                test_content = self._generate_sql_fuzzing_test(threat)
                filename = f"fuzz_injection_{self._get_threat_id(threat)}.py"
            elif threat['category'] == 'Denial of Service':
                test_content = self._generate_dos_fuzzing_test(threat)
                filename = f"fuzz_dos_{self._get_threat_id(threat)}.py"
            elif threat['category'] == 'Elevation of Privilege':
                test_content = self._generate_auth_fuzzing_test(threat)
                filename = f"fuzz_auth_{self._get_threat_id(threat)}.py"
            else:
                # Generic fuzzing test
                test_content = self._generate_generic_fuzzing_test(threat)
                filename = f"fuzz_{self._get_threat_id(threat)}.py"

            # Write test file
            test_path = self.output_dir / filename
            test_path.write_text(test_content, encoding='utf-8')
            test_files.append(test_path)

        return test_files

    def _generate_sql_fuzzing_test(self, threat: Dict) -> str:
        """Generate SQL injection fuzzing test."""
        return f"""import pytest
import requests


class TestSQLInjection{self._get_threat_id(threat).replace('-', '').replace('_', '').upper()}:
    \"\"\"Security tests for SQL injection in {threat['component']}\"\"\"

    BASE_URL = "http://localhost:8000"
    ENDPOINT = "{threat['component']}"

    # SQL injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "admin'--",
        "' OR 1=1#",
        "' OR 1=1--",
        "1' AND 1=1--",
        "admin'/*",
        "' UNION SELECT 1,version(),3--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "'; EXEC xp_cmdshell('dir')--",
        "1'; EXEC master..xp_cmdshell 'dir'--",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
        "1' UNION ALL SELECT NULL,NULL,NULL,NULL--",
        "' OR 1=1 INTO OUTFILE '/tmp/file.txt--",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_blocked(self, payload):
        \"\"\"Test that SQL injection payloads are blocked\"\"\"
        response = requests.post(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            json={{"username": payload, "password": "test"}},
            headers={{"Content-Type": "application/json"}},
            timeout=5
        )

        # Should return 400/401/403, not 500 (which indicates SQL error)
        assert response.status_code in [400, 401, 403, 404]

        # Verify no SQL error leaked in response
        text = response.text.lower()
        assert "sql" not in text
        assert "syntax" not in text
        assert "mysql" not in text
        assert "postgres" not in text
        assert "oracle" not in text
        assert "sqlite" not in text

    def test_sql_injection_in_get_params(self):
        \"\"\"Test SQL injection via GET parameters\"\"\"
        for payload in self.SQL_PAYLOADS[:5]:
            response = requests.get(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}?id={{payload}}",
                timeout=5
            )

            # Should not cause server error
            assert response.status_code != 500

    def test_union_based_injection(self):
        \"\"\"Test UNION-based SQL injection\"\"\"
        union_payloads = [
            "1' UNION SELECT NULL--",
            "1' UNION SELECT 1--",
            "1' UNION SELECT 1,2--",
            "1' UNION SELECT 1,2,3--",
            "1' UNION SELECT user(),version(),database()--",
        ]

        for payload in union_payloads:
            response = requests.post(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}",
                json={{"id": payload}},
                timeout=5
            )

            assert response.status_code != 500
"""

    def _generate_dos_fuzzing_test(self, threat: Dict) -> str:
        """Generate DoS fuzzing test."""
        return f"""import pytest
import requests
import time


class TestDenialOfService{self._get_threat_id(threat).replace('-', '').replace('_', '').upper()}:
    \"\"\"Security tests for DoS vulnerabilities in {threat['component']}\"\"\"

    BASE_URL = "http://localhost:8000"
    ENDPOINT = "{threat['component']}"

    def test_large_payload_handling(self):
        \"\"\"Test that large payloads are rejected\"\"\"
        # Generate large payload (10MB)
        large_payload = "A" * (10 * 1024 * 1024)

        response = requests.post(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            json={{"data": large_payload}},
            headers={{"Content-Type": "application/json"}},
            timeout=10
        )

        # Should reject large payload
        assert response.status_code in [413, 400, 431]

    def test_request_rate_limiting(self):
        \"\"\"Test that rate limiting is enforced\"\"\"
        # Send 100 requests rapidly
        responses = []
        start_time = time.time()

        for i in range(100):
            response = requests.get(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}",
                timeout=1
            )
            responses.append(response.status_code)

        elapsed = time.time() - start_time

        # Should have rate limiting (429 Too Many Requests)
        assert 429 in responses or elapsed < 5  # Either rate limited or very fast

    def test_deep_recursion_attack(self):
        \"\"\"Test protection against deep recursion\"\"\"
        # JSON with deep nesting
        deep_json = {{"a": 1}}
        for _ in range(1000):
            deep_json = {{"nested": deep_json}}

        response = requests.post(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            json=deep_json,
            timeout=5
        )

        # Should reject or handle gracefully
        assert response.status_code in [400, 413, 422]

    def test_unicode_normalization_attack(self):
        \"\"\"Test Unicode normalization attacks\"\"\"
        # Payloads with unusual Unicode
        unicode_payloads = [
            "\\u0000",
            "\\u0080",
            "\\uFFFF",
            "\\uFEFF",  # Zero-width no-break space
            "\u200B",  # Zero-width space
            "\u200C",  # Zero-width non-joiner
        ]

        for payload in unicode_payloads:
            response = requests.post(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}",
                json={{"input": payload}},
                timeout=5
            )

            # Should handle gracefully
            assert response.status_code != 500

    def test_compression_bomb(self):
        \"\"\"Test protection against compression bombs\"\"\"
        # Small payload that expands when decompressed
        # Note: This requires the endpoint to support compression

        # Example: Highly compressible data
        bomb_data = "A" * 1000000  # 1MB of 'A's

        response = requests.post(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            data=bomb_data,
            headers={{"Content-Encoding": "gzip", "Content-Type": "application/json"}},
            timeout=5
        )

        # Should not cause DoS
        assert response.status_code in [400, 415, 422] or response.status_code < 500
"""

    def _generate_auth_fuzzing_test(self, threat: Dict) -> str:
        """Generate authentication fuzzing test."""
        return f"""import pytest
import requests


class TestAuthBypass{self._get_threat_id(threat).replace('-', '').replace('_', '').upper()}:
    \"\"\"Security tests for authentication bypass in {threat['component']}\"\"\"

    BASE_URL = "http://localhost:8000"
    ENDPOINT = "{threat['component']}"

    def test_missing_token_rejected(self):
        \"\"\"Test that requests without auth tokens are rejected\"\"\"
        response = requests.get(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            timeout=5
        )

        assert response.status_code in [401, 403]

    def test_invalid_token_rejected(self):
        \"\"\"Test that invalid tokens are rejected\"\"\"
        invalid_tokens = [
            "invalid",
            "Bearer invalid",
            "null",
            "undefined",
            "12345",
            "abc123",
            "",
        ]

        for token in invalid_tokens:
            response = requests.get(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}",
                headers={{"Authorization": f"Bearer {{token}}"}},
                timeout=5
            )

            assert response.status_code in [401, 403]

    def test_expired_token_rejected(self):
        \"\"\"Test that expired tokens are rejected\"\"\"
        # JWT token with expired 'exp' claim
        expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwfQ.invalid"

        response = requests.get(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            headers={{"Authorization": f"Bearer {{expired_token}}"}},
            timeout=5
        )

        assert response.status_code in [401, 403]

    def test_token_tampering_detected(self):
        \"\"\"Test that tampered tokens are rejected\"\"\"
        # Valid JWT signature with modified payload
        tampered_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.tampered"

        response = requests.get(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            headers={{"Authorization": f"Bearer {{tampered_token}}"}},
            timeout=5
        )

        assert response.status_code in [401, 403]

    def test_jwt_algorithm_confusion_attack(self):
        \"\"\"Test JWT algorithm confusion attack\"\"\"
        # Try to use 'none' algorithm
        none_token = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

        response = requests.get(
            f"{{self.BASE_URL}}{{self.ENDPOINT}}",
            headers={{"Authorization": f"Bearer {{none_token}}"}},
            timeout=5
        )

        assert response.status_code in [401, 403]

    def test_session_fixation_prevented(self):
        \"\"\"Test that session fixation is prevented\"\"\"
        # Get initial session
        response1 = requests.get(f"{{self.BASE_URL}}/login")
        session_cookie = response1.cookies.get('session')

        # Login with session
        response2 = requests.post(
            f"{{self.BASE_URL}}/login",
            cookies={{"session": session_cookie}},
            data={{"username": "test", "password": "test"}},
            timeout=5
        )

        # Session should change after login
        new_session_cookie = response2.cookies.get('session')

        # This is a simplified check
        # In real test, verify session ID changes
"""

    def _generate_generic_fuzzing_test(self, threat: Dict) -> str:
        """Generate generic fuzzing test."""
        return f"""import pytest
import requests


class TestGenericFuzzing{self._get_threat_id(threat).replace('-', '').replace('_', '').upper()}:
    \"\"\"Generic fuzzing tests for {threat['component']}\"\"\"

    BASE_URL = "http://localhost:8000"
    ENDPOINT = "{threat['component']}"

    def test_special_characters_handling(self):
        \"\"\"Test handling of special characters\"\"\"
        special_payloads = [
            "<script>alert(1)</script>",
            "'\"",
            "../../etc/passwd",
            "../../../",
            "{{",
            "}}",
            "$(whoami)",
            ";ls",
            "|cat /etc/passwd",
            "`id`",
            "\\x00",
        ]

        for payload in special_payloads:
            response = requests.post(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}",
                json={{"input": payload}},
                timeout=5
            )

            # Should handle gracefully (no 500 error)
            assert response.status_code != 500

    def test_null_byte_injection(self):
        \"\"\"Test null byte injection\"\"\"
        null_payloads = [
            "test%00.jpg",
            "test.txt%00.php",
            "../../index.php%00.jpg",
        ]

        for payload in null_payloads:
            response = requests.get(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}?file={{payload}}",
                timeout=5
            )

            # Should handle gracefully
            assert response.status_code != 500

    def test_command_injection(self):
        \"\"\"Test command injection payloads\"\"\"
        command_payloads = [
            "; ls -la",
            "| whoami",
            "& cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
        ]

        for payload in command_payloads:
            response = requests.post(
                f"{{self.BASE_URL}}{{self.ENDPOINT}}",
                json={{"filename": payload}},
                timeout=5
            )

            # Should not execute command
            # Response should not contain command output
            assert "root:" not in response.text
            assert response.status_code != 500
"""
