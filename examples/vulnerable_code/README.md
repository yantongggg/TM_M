# Vulnerable Code Examples

**⚠️ WARNING: Do NOT use this code in production!**

This directory contains intentionally vulnerable code for testing the SAST (Static Application Security Testing) scanning capabilities.

## Purpose

These example files demonstrate common security vulnerabilities that the Semgrep SAST scanner can detect. They are useful for:

- **Testing the security pipeline**: Verify that SAST scanning is working correctly
- **Demonstration**: Show team members what kinds of vulnerabilities are detected
- **Education**: Learn to identify security anti-patterns in code
- **Validation**: Confirm that fixes properly address detected issues

## Files

### `test_vulnerabilities.py`

Python examples with intentional vulnerabilities:
1. SQL Injection (CWE-89)
2. Command Injection (CWE-77)
3. Hardcoded Secrets (CWE-798)
4. Cross-Site Scripting (CWE-79)
5. Insecure Deserialization (CWE-502)
6. Path Traversal (CWE-22)
7. Weak Cryptography (CWE-327)
8. Information Disclosure (CWE-200)
9. Weak Random Number Generation (CWE-338)
10. Insecure Direct Object Reference (CWE-639)

Each vulnerability includes:
- ❌ **Vulnerable implementation**: Demonstrates the security issue
- ✅ **Safe implementation**: Shows how to fix it properly
- 📖 **CWE reference**: Links to industry-standard vulnerability descriptions

### `test_vulnerabilities.js`

JavaScript/Node.js examples with intentional vulnerabilities:
1. SQL Injection (CWE-89)
2. Command Injection (CWE-77)
3. Hardcoded Secrets (CWE-798)
4. Cross-Site Scripting (CWE-79)
5. Code Injection via eval() (CWE-95)
6. Weak Cryptography (CWE-327)
7. Weak Random Number Generation (CWE-338)
8. Path Traversal (CWE-22)
9. Insecure Direct Object Reference (CWE-639)
10. Regular Expression DoS (CWE-1333)
11. Sensitive Data in URL (CWE-598)
12. Missing Rate Limiting (CWE-307)

## How to Use

### 1. Test SAST Scanning

Push this file to a test branch and create a PR:

```bash
git checkout -b test/sast-detection
git add examples/vulnerable_code/
git commit -m "test: Add vulnerable code for SAST testing"
git push origin test/sast-detection
```

The SAST scanner should detect multiple vulnerabilities and report them in:
- PR comments
- `sast-report-{n}` artifact
- Unified `security-report-{n}` artifact

### 2. Verify Detection

Check that the scanner finds:
- ✅ SQL injection patterns
- ✅ Command injection via `os.system()` / `exec()`
- ✅ Hardcoded API keys and passwords
- ✅ XSS via template strings
- ✅ Weak cryptographic algorithms (MD5)
- ✅ Weak random number generation
- ✅ Path traversal vulnerabilities

### 3. Practice Fixing

After seeing the detection results:
1. Review the specific finding in the XML report
2. Read the mitigation recommendations
3. Compare the vulnerable vs safe implementations
4. Apply similar patterns to your production code

### 4. Validation

To verify fixes work correctly:
1. Replace vulnerable code with safe implementation
2. Commit and push changes
3. Verify the finding no longer appears in the report

## Expected SAST Findings

When you run SAST scanning on these files, you should see findings similar to:

### Python File (test_vulnerabilities.py)

| Line | Rule | Severity | Vulnerability |
|------|------|----------|---------------|
| ~18 | `python.sql-injection` | High | SQL injection via f-string |
| ~38 | `python.os.system` | High | Command injection via os.system |
| ~56 | `hardcoded.api-key` | Critical | Hardcoded API key |
| ~58 | `hardcoded.password` | Critical | Hardcoded password |
| ~68 | `python.flask.xss` | High | XSS via unsanitized input |
| ~88 | `python.pickle.load` | High | Unsafe deserialization |
| ~103 | `python.path-traversal` | High | Path traversal vulnerability |
| ~120 | `weak-crypto.md5` | Medium | Using MD5 for passwords |
| ~157 | `weak-random` | Medium | Using random module for tokens |
| ~172 | `idor.access-control` | High | Missing authorization check |

### JavaScript File (test_vulnerabilities.js)

| Line | Rule | Severity | Vulnerability |
|------|------|----------|---------------|
| ~14 | `javascript.sql-injection` | High | SQL injection via template literal |
| ~26 | `javascript.exec` | High | Command injection via exec() |
| ~43 | `hardcoded.api-key` | Critical | Hardcoded API key |
| ~45 | `hardcoded.password` | Critical | Hardcoded password |
| ~56 | `javascript.xss` | High | XSS via template literal |
| ~68 | `javascript.eval` | High | Code injection via eval() |
| ~95 | `weak-crypto.md5` | Medium | Using MD5 for passwords |
| ~113 | `weak-random` | Medium | Using Math.random() for tokens |
| ~127 | `javascript.path-traversal` | High | Path traversal vulnerability |
| ~153 | `idor.access-control` | High | Missing authorization check |

## Suppression in Production

**Important:** These files are excluded from SAST scanning via `.semgrepignore`:

```
examples/vulnerable_code/
```

This prevents test code from generating false positives in production scans.

## Learning Resources

For each vulnerability type, refer to:
- **CWE (Common Weakness Enumeration)**: Detailed vulnerability descriptions
- **OWASP Top 10**: Most critical web application security risks
- **Semgrep Rules Repository**: Community-maintained detection rules
- **SECURITY_SCAN_README.md**: Comprehensive guide for fixing findings

## Common Vulnerability Patterns

### Injection Vulnerabilities

**Pattern:** Unsanitized user input concatenated into commands/queries

**Detection:** Look for string concatenation with user input:
- Python: `f"SELECT * FROM users WHERE id = {user_input}"`
- JavaScript: `` `SELECT * FROM users WHERE id = ${user_input}` ``

**Fix:** Use parameterized queries / prepared statements

### Cryptographic Issues

**Pattern:** Using outdated or weak algorithms

**Detection:** Look for:
- MD5, SHA1 for passwords
- `random` / `Math.random()` for security-sensitive data
- Hardcoded encryption keys

**Fix:** Use strong, modern algorithms with proper libraries

### Authentication & Authorization

**Pattern:** Missing security checks in sensitive operations

**Detection:** Look for:
- Direct object access without ownership checks
- Missing rate limiting on authentication endpoints
- Sensitive data in URLs

**Fix:** Implement proper access controls and rate limiting

## Testing Checklist

When testing the SAST pipeline:

- [ ] SAST workflow runs successfully on PR
- [ ] `sast-report-{n}.xml` artifact is generated
- [ ] PR comment includes SAST summary
- [ ] Detected vulnerabilities match expected findings
- [ ] Severity levels are appropriate
- [ ] Mitigation recommendations are helpful
- [ ] Replacing vulnerable code with safe code removes findings
- [ ] `.semgrepignore` correctly excludes test files

## Support

If SAST scanning doesn't detect these vulnerabilities:
1. Check workflow logs for Semgrep execution
2. Verify `.semgrepignore` isn't excluding test files
3. Confirm Semgrep configuration uses `config: auto`
4. Review Semgrep action version in workflow file

## Disclaimer

These examples are simplified for educational purposes. Real-world vulnerabilities may be:
- More complex and harder to detect
- Spread across multiple files/modules
- Dependent on specific framework versions
- Context-dependent (may not be exploitable in certain scenarios)

Always review findings in the context of your actual codebase and threat model.
