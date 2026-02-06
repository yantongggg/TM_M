"""
Playwright Test Generator for Web Applications

Generates Playwright security tests for web applications
based on detected threats.
"""

from pathlib import Path
from typing import List, Dict
from .test_gen import BaseTestGenerator


class PlaywrightTestGenerator(BaseTestGenerator):
    """
    Generate Playwright security tests for web applications.

    Generates .spec.ts test files that can be run with Playwright
    to verify security controls against XSS, injection, and other
    web vulnerabilities.
    """

    def generate_tests(self) -> List[Path]:
        """
        Generate Playwright test files for web threats.

        Returns:
            List of generated test file paths
        """
        self._ensure_output_dir()
        test_files = []

        for threat in self.threats:
            # Determine test type based on threat category
            if threat['category'] in ['Spoofing', 'Tampering', 'Information Disclosure']:
                test_content = self._generate_xss_test(threat)
                filename = f"security_xss_{self._get_threat_id(threat)}.spec.ts"
            elif threat['category'] == 'Injection':
                test_content = self._generate_injection_test(threat)
                filename = f"security_injection_{self._get_threat_id(threat)}.spec.ts"
            elif threat['category'] == 'Information Disclosure':
                test_content = self._generate_data_leak_test(threat)
                filename = f"security_data_leak_{self._get_threat_id(threat)}.spec.ts"
            elif threat['category'] == 'Elevation of Privilege':
                test_content = self._generate_auth_test(threat)
                filename = f"security_auth_{self._get_threat_id(threat)}.spec.ts"
            else:
                # Generic security test
                test_content = self._generate_generic_test(threat)
                filename = f"security_{self._get_threat_id(threat)}.spec.ts"

            # Write test file
            test_path = self.output_dir / filename
            test_path.write_text(test_content, encoding='utf-8')
            test_files.append(test_path)

        return test_files

    def _generate_xss_test(self, threat: Dict) -> str:
        """Generate XSS test using Playwright."""
        return f"""import {{ test, expect }} from '@playwright/test';

test.describe('Security: {threat['title']}', () => {{
  test('should block XSS attack in {threat['component']}', async ({{ page }}) => {{
    // Navigate to vulnerable component
    await page.goto('/{threat['component']}');

    // Attempt XSS injection
    const xssPayloads = [
      '<script>alert(document.cookie)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      'javascript:alert(1)'
    ];

    for (const payload of xssPayloads) {{
      // Try to inject XSS
      await page.fill('input[name="userInput"], textarea[name="content"], input[type="text"]', payload);
      await page.click('button[type="submit"], input[type="submit"]');

      // Verify XSS is blocked
      await page.waitForURL('**/success', {{ timeout: 5000 }}).catch(() => {{}});

      const content = await page.content();
      expect(content).not.toContain(payload);
      expect(await page.locator('body').innerText()).not.toMatch(/<script>/);
      expect(await page.locator('body').innerText()).not.toMatch(/javascript:/);
    }}
  }});

  test('should sanitize HTML output', async ({{ page }}) => {{
    await page.goto('/{threat['component']}');

    // Input HTML tags
    const htmlInput = '<p>Test</p><script>alert(1)</script>';
    await page.fill('input[name="userInput"], textarea[name="content"]', htmlInput);
    await page.click('button[type="submit"]');

    // Verify HTML is escaped
    const content = await page.content();
    expect(content).not.toContain('<script>');
    expect(content).toContain('&lt;');
  }});
}});
"""

    def _generate_injection_test(self, threat: Dict) -> str:
        """Generate SQL injection test."""
        return f"""import {{ test, expect }} from '@playwright/test';

test.describe('Security: {threat['title']}', () => {{
  test('should block SQL injection in {threat['component']}', async ({{ page, request }}) => {{
    // SQL injection payloads
    const sqlPayloads = [
      "' OR '1'='1",
      "1' UNION SELECT NULL--",
      "'; DROP TABLE users--",
      "admin'--",
      "' OR 1=1#",
      "' OR 1=1--",
      "1' AND 1=1--"
    ];

    for (const payload of sqlPayloads) {{
      // Try injection via API
      const response = await request.post('/api/{threat['component']}', {{
        data: {{
          username: payload,
          password: 'test'
        }}
      }});

      // Should return 400/401, not 500 (which would indicate SQL error)
      expect([400, 401, 403]).toContain(response.status());

      // Verify no SQL error leaked
      const text = await response.text();
      expect(text.toLowerCase()).not.toMatch(/sql/);
      expect(text.toLowerCase()).not.toMatch(/syntax/);
      expect(text.toLowerCase()).not.toMatch(/mysql/);
      expect(text.toLowerCase()).not.toMatch(/postgres/);
    }}
  }});

  test('should handle NoSQL injection', async ({{ page, request }}) => {{
    const nosqlPayloads = [
      '{{"$ne": null}}',
      '{{"$gt": ""}}',
      '{{"$regex": ".*"}}'
    ];

    for (const payload of nosqlPayloads) {{
      const response = await request.post('/api/{threat['component']}', {{
        data: {{
          username: payload,
          password: 'test'
        }}
      }});

      // Should not bypass authentication
      expect([400, 401, 403]).toContain(response.status());
    }}
  }});
}});
"""

    def _generate_data_leak_test(self, threat: Dict) -> str:
        """Generate data leak test."""
        return f"""import {{ test, expect }} from '@playwright/test';

test.describe('Security: {threat['title']}', () => {{
  test('should not leak sensitive data in page source', async ({{ page }}) => {{
    await page.goto('/{threat['component']}');

    // Get page source
    const content = await page.content();

    // Check for sensitive data leaks
    const sensitivePatterns = [
      /password["\']?\s*[:=]\s*["\']?[\w]+/i,
      /api_key["\']?\s*[:=]\s*["\']?[\w-]+/i,
      /secret["\']?\s*[:=]\s*["\']?[\w]+/i,
      /token["\']?\s*[:=]\s*["\']?[\w.-]+/i
    ];

    for (const pattern of sensitivePatterns) {{
      const matches = content.match(pattern);
      if (matches) {{
        // Verify matches are not actual secrets (false positives)
        for (const match of matches) {{
          // These should be placeholders, not real secrets
          expect(match.toLowerCase()).toMatch(/(placeholder|example|test|xxx|undefined|null)/);
        }}
      }}
    }}
  }});

  test('should not expose sensitive data in localStorage', async ({{ page }}) => {{
    await page.goto('/{threat['component']}');

    // Check localStorage
    const localStorage = await page.evaluate(() => {{
      const data = {{}};
      for (let i = 0; i < localStorage.length; i++) {{
        const key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
      }}
      return data;
    }});

    // Verify no sensitive data in localStorage
    for (const [key, value] of Object.entries(localStorage)) {{
      expect(key.toLowerCase()).not.toMatch(/(password|secret|api_key|token)/);
      expect(String(value).toLowerCase()).not.toMatch(/(password|secret|api_key|token)/);
    }}
  }});

  test('should set secure cookie flags', async ({{ page, context }}) => {{
    await page.goto('/{threat['component']}');

    // Get cookies
    const cookies = await context.cookies();

    // Verify secure cookie attributes
    for (const cookie of cookies) {{
      // Session cookies should have HttpOnly
      if (cookie.name.toLowerCase().includes('session') ||
          cookie.name.toLowerCase().includes('token')) {{
        expect(cookie.httpOnly).toBe(true);
        expect(cookie.secure).toBe(true);
        expect(cookie.sameSite).toBe('Strict' || 'Lax');
      }}
    }}
  }});
}});
"""

    def _generate_auth_test(self, threat: Dict) -> str:
        """Generate authentication/authorization test."""
        return f"""import {{ test, expect }} from '@playwright/test';

test.describe('Security: {threat['title']}', () => {{
  test('should prevent unauthorized access to {threat['component']}', async ({{ page }}) => {{
    // Try to access protected resource without authentication
    await page.goto('/{threat['component']}');

    // Should redirect to login or show 401/403
    const url = page.url();
    expect(url).toMatch(/(login|signin|auth)/);

    // Or show error
    const content = await page.content();
    const isUnauthorized = content.match(/(401|403|unauthorized|forbidden)/i);
    expect(isUnauthorized).toBeTruthy();
  }});

  test('should prevent privilege escalation', async ({{ page, request }}) => {{
    // Login as regular user
    await page.goto('/login');
    await page.fill('input[name="username"]', 'regularuser');
    await page.fill('input[name="password"]', 'password123');
    await page.click('button[type="submit"]');

    // Try to access admin resource
    const response = await request.get('/{threat['component']}');

    // Should be forbidden
    expect([401, 403, 404]).toContain(response.status());
  }});

  test('should validate session on each request', async ({{ page, context }}) => {{
    // Login
    await page.goto('/login');
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'password123');
    await page.click('button[type="submit"]');

    // Clear session cookie
    await context.clearCookies();

    // Try to access protected resource
    await page.goto('/{threat['component']}');

    // Should redirect to login
    const url = page.url();
    expect(url).toMatch(/(login|signin|auth)/);
  }});
}});
"""

    def _generate_generic_test(self, threat: Dict) -> str:
        """Generate generic security test."""
        return f"""import {{ test, expect }} from '@playwright/test';

test.describe('Security: {threat['title']}', () => {{
  test('should implement security controls for {threat['component']}', async ({{ page }}) => {{
    // Navigate to component
    await page.goto('/{threat['component']}');

    // Verify component loads
    await expect(page).toHaveURL(/{threat['component']}/);

    // TODO: Implement specific test for {threat['category']}
    // This is a placeholder test for the detected threat

    // Verify no obvious security issues
    const content = await page.content();

    // Check for debug information
    expect(content).not.toContain('debug');
    expect(content).not.toContain('trace');
    expect(content).not.toContain('stack trace');

    // Check for version information
    expect(content).not.toMatch(/version:\s*\d+\.\d+/);
  }});
}});
"""
