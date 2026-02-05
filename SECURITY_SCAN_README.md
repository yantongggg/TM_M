# Security Scanning Guide

This repository includes automated security scanning tools that combine **design-level threat modeling** (STRIDE) with **code-level static analysis** (SAST) to provide comprehensive security coverage.

## 📋 Table of Contents

- [Overview](#overview)
- [Security Tools](#security-tools)
- [Understanding Reports](#understanding-reports)
- [Severity Levels](#severity-levels)
- [Operating Modes](#operating-modes)
- [Common Vulnerabilities Detected](#common-vulnerabilities-detected)
- [How to Fix Findings](#how-to-fix-findings)
- [Suppressing False Positives](#suppressing-false-positives)
- [Graduation Checklist](#graduation-checklist)

---

## Overview

The security scanning pipeline runs automatically on:
- Push to `main`, `master`, or `develop` branches
- All pull requests targeting these branches
- Manual workflow dispatch

### What Gets Scanned?

| Security Layer | Tool | What It Detects |
|---|---|---|
| **Design-Level** | STRIDE Threat Modeling | Architectural vulnerabilities, trust boundary issues, data flow risks |
| **Code-Level** | Semgrep (SAST) | SQL injection, XSS, command injection, hardcoded secrets, insecure configurations |

### Reports Generated

1. **Design Threat Report** (`threat-report-{n}.xml`) - STRIDE analysis of architecture.yaml
2. **SAST Report** (`sast-report-{n}.xml`) - Semgrep code scanning results
3. **Unified Security Report** (`security-report-{n}.xml`) - Merged findings from both sources

---

## Security Tools

### Tool 1: STRIDE Threat Modeling

**Purpose:** Design-level security analysis using the STRIDE methodology.

**How it works:**
- Analyzes `architecture.yaml` for components, data flows, and trust boundaries
- Uses AI (Zhipu GLM-4) to identify potential threats
- Categorizes threats by: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege

**Strengths:**
- Catches architectural issues before code is written
- Identifies missing security controls
- Reviews authentication flows, authorization, data encryption
- Evaluates compliance requirements

**Limitations:**
- Cannot detect implementation bugs
- Depends on accurate architecture documentation
- May produce theoretical threats

### Tool 2: Semgrep (SAST)

**Purpose:** Static code analysis for implementation vulnerabilities.

**How it works:**
- Scans source code for security anti-patterns
- Uses community-maintained rules (OWASP Top 10, CWE Top 25)
- Supports 20+ languages (Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, etc.)
- Fast pattern matching (typically 30-60 seconds)

**Strengths:**
- Detects real bugs in production code
- Fast feedback suitable for CI/CD
- Customizable rules for project-specific patterns
- Can auto-fix some vulnerabilities

**Limitations:**
- May produce false positives
- Limited to static analysis (can't detect runtime issues)
- Doesn't track data flow across files (taint analysis)

---

## Understanding Reports

### XML Report Structure

```xml
<ThreatModel>
  <Summary>
    <SystemName>System Name</SystemName>
    <AnalysisDate>2026-02-05</AnalysisDate>
    <TotalThreats>15</TotalThreats>
    <CriticalCount>2</CriticalCount>
    <HighCount>4</HighCount>
    <MediumCount>6</MediumCount>
    <LowCount>3</LowCount>
    <DesignThreats>8</DesignThreats>
    <CodeThreats>7</CodeThreats>
    <Overview>Brief summary of findings...</Overview>
  </Summary>
  <Threats>
    <Threat category="Tampering" severity="Critical" source="design">
      <Title>Payment data without validation</Title>
      <Component>PaymentAPI</Component>
      <Description>Detailed threat description...</Description>
      <AttackScenario>Step-by-step attack scenario...</AttackScenario>
      <Impact>Technical and business impact...</Impact>
      <Likelihood>High</Likelihood>
      <Mitigation>Specific remediation steps...</Mitigation>
      <References>OWASP, CWE references...</References>
    </Threat>
    <Threat category="Information Disclosure" severity="High" source="code">
      <Title>SQL Injection in user_query()</Title>
      <Component>app/db.py:45</Component>
      <Description>Vulnerability details...</Description>
      <RuleID>python.lang.security.audit.sql-injection</RuleID>
      <CWE>CWE-89</CWE>
      <AttackScenario>How to exploit...</AttackScenario>
      <Impact>Impact description...</Impact>
      <Likelihood>Medium</Likelihood>
      <Mitigation>Fix recommendations...</Mitigation>
      <References>Semgrep rule, CWE link...</References>
    </Threat>
  </Threats>
</ThreatModel>
```

### Accessing Reports

1. Go to the **Actions** tab in your GitHub repository
2. Click on the latest workflow run
3. Scroll to **Artifacts** at the bottom
4. Download the desired report:
   - `security-report-{n}` - Unified report (recommended)
   - `threat-report-{n}` - Design-level threats only
   - `sast-report-{n}` - Code-level threats only

---

## Severity Levels

### Critical
**Definition:** Direct path to data breach, critical system compromise, or severe compliance violation.

**Examples:**
- Hardcoded credentials in source code
- SQL injection in authentication logic
- No encryption on sensitive data in transit
- Authentication bypass vulnerabilities

**Action Required:** Fix immediately before merging.

---

### High
**Definition:** Significant security impact with realistic exploit path.

**Examples:**
- SQL injection in non-critical functions
- Cross-site scripting (XSS) vulnerabilities
- Insecure direct object references (IDOR)
- Command injection with user input

**Action Required:** Fix before deploying to production.

---

### Medium
**Definition:** Moderate impact or lower likelihood exploits.

**Examples:**
- Missing security headers
- Overly permissive CORS configuration
- Insufficient logging/audit trails
- Weak password policies

**Action Required:** Address within next sprint.

---

### Low
**Definition:** Minor issues or theoretical threats with low likelihood.

**Examples:**
- Outdated dependencies with no known exploits
- Missing error handling
- Verbose error messages
- Lack of HTTP Strict Transport Security (HSTS)

**Action Required:** Fix when time permits, but track for technical debt.

---

## Operating Modes

The security pipeline operates in two modes, controlled by the `SECURITY_MODE` environment variable.

### Audit Mode (Default)
**Configuration:** `SECURITY_MODE: audit`

**Behavior:**
- Runs all security scans
- Generates and uploads reports as artifacts
- Comments on PRs with findings
- **Never fails the build**, regardless of severity
- Allows team to establish baseline security posture

**When to Use:**
- Initial deployment (first 2-4 weeks)
- Understanding existing security debt
- Identifying and suppressing false positives
- Getting team buy-in

**CI/CD Behavior:**
```yaml
# In .github/workflows/threat-modeling.yml
env:
  SECURITY_MODE: audit

# Build will ALWAYS pass, even with Critical findings
```

---

### Block Mode
**Configuration:** `SECURITY_MODE: block`

**Behavior:**
- Runs all security scans
- Generates and uploads reports
- Comments on PRs with findings
- **Fails the build** on Critical or High severity findings
- Prevents merging of vulnerable code

**When to Use:**
- After audit phase graduation
- Team has security issue response process
- Existing findings are documented and triaged
- Only new code must meet security standards

**CI/CD Behavior:**
```yaml
# In .github/workflows/threat-modeling.yml
env:
  SECURITY_MODE: block

# Build FAILS if Critical or High findings detected
# Exit code 1 prevents merge
```

---

## Common Vulnerabilities Detected

### SQL Injection

**Threat Category:** Tampering / Information Disclosure

**Example Vulnerable Code:**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    return db.execute(query)
```

**Fix:**
```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"  # SAFE
    return db.execute(query, (user_id,))
```

**CWE:** CWE-89

---

### Cross-Site Scripting (XSS)

**Threat Category:** Tampering / Information Disclosure

**Example Vulnerable Code:**
```javascript
function renderGreeting(username) {
    return `<h1>Hello ${username}</h1>`;  // VULNERABLE
}
```

**Fix:**
```javascript
import { sanitize } from 'sanitize-html';

function renderGreeting(username) {
    const clean = sanitize(username);  // SAFE
    return `<h1>Hello ${clean}</h1>`;
}
```

**CWE:** CWE-79

---

### Command Injection

**Threat Category:** Elevation of Privilege / Tampering

**Example Vulnerable Code:**
```python
import os

def process_file(filename):
    os.system(f"cat {filename}")  # VULNERABLE
```

**Fix:**
```python
import subprocess

def process_file(filename):
    # Validate filename is just a filename, not a path
    if not filename.isalnum():
        raise ValueError("Invalid filename")
    subprocess.run(['cat', filename], check=True)  # SAFE
```

**CWE:** CWE-77

---

### Hardcoded Secrets

**Threat Category:** Information Disclosure / Spoofing

**Example Vulnerable Code:**
```python
API_KEY = "sk_live_abc123..."  # VULNERABLE
DATABASE_PASSWORD = "admin123"  # VULNERABLE
```

**Fix:**
```python
import os

API_KEY = os.environ.get('API_KEY')  # SAFE
DATABASE_PASSWORD = os.environ.get('DB_PASSWORD')  # SAFE
```

**CWE:** CWE-798

---

### Insecure Direct Object Reference (IDOR)

**Threat Category:** Elevation of Privilege / Information Disclosure

**Example Vulnerable Code:**
```python
@app.route('/orders/<order_id>')
def get_order(order_id):
    # No authorization check - any user can access any order
    return Order.query.get(order_id)  # VULNERABLE
```

**Fix:**
```python
@app.route('/orders/<order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    if order.user_id != current_user.id:  # SAFE
        abort(403)
    return order
```

**CWE:** CWE-639

---

## How to Fix Findings

### Step 1: Review the Finding

1. Download the security report XML
2. Locate the threat by title
3. Review:
   - **Description** - What is the vulnerability?
   - **Component** - Where is it located?
   - **Attack Scenario** - How could it be exploited?
   - **Impact** - What's the damage?

### Step 2: Understand the Fix

Review the **Mitigation** section for specific remediation steps, which typically include:
- Code changes needed
- Configuration updates
- Architecture modifications
- Security best practices

### Step 3: Implement the Fix

1. Create a new branch: `git checkout -b fix/security-issue-XXX`
2. Implement the recommended changes
3. Add tests to prevent regression
4. Commit with clear message: `fix: Resolve SQL injection in user_query()`

### Step 4: Verify

1. Push your changes
2. Wait for the security scan to run
3. Verify the finding no longer appears
4. Review any new findings introduced by your changes

### Step 5: Merge

Once the scan passes:
- Update your PR with the fix details
- Reference the original finding
- Merge after approval

---

## Suppressing False Positives

### What is a False Positive?

A false positive occurs when the security scanner flags code that is actually safe. This can happen when:
- Input validation happens elsewhere in the code
- The code path is unreachable
- The vulnerability is mitigated by framework or library
- Custom security controls are in place

### How to Suppress

#### Method 1: Inline Suppression (Semgrep)

For code-level findings, add an inline comment:

```python
def process_data(user_input):
    # nosemgrep: python.lang.security.audit.sql-injection
    # We've validated user_input is alphanumeric before this call
    query = f"SELECT * FROM data WHERE value = '{user_input}'"
    return db.execute(query)
```

#### Method 2: File Exclusion

Add files/directories to `.semgrepignore`:

```
# Exclude test files with intentional vulnerabilities
**/test_vulnerabilities.py
**/security_tests/
```

#### Method 3: Architecture Documentation

For design-level threats, add explicit documentation to `architecture.yaml`:

```yaml
components:
  - name: PaymentAPI
    security_controls:
      - description: "SQL injection prevention"
        implementation: "Using parameterized queries via SQLAlchemy ORM"
        validation: "Validated by annual penetration test"
```

#### Method 4: Accepted Risk

For issues that are documented as accepted risk:

1. Create a GitHub issue with the title: `[Security] Accepted Risk: {Title}`
2. Document:
   - Why this is an accepted risk
   - Business justification
   - Compensating controls (if any)
   - Review date
3. Reference this issue in the PR

**Example:**

```markdown
## Accepted Risk: Debug Mode in Production

**Finding:** Debug mode enabled in production logs
**Severity:** Medium
**Decision:** Accepted for 6 months
**Justification:**
- Debug logs essential for troubleshooting production issues
- Rate limiting prevents log flooding
- Logs are encrypted at rest
- Access restricted to operations team
**Compensating Controls:**
- Log aggregation via CloudWatch
- Monthly access reviews
- Plan to migrate to structured logging by Q3
**Review Date:** 2026-08-01
```

---

## Graduation Checklist

Transitioning from **Audit Mode** to **Block Mode** requires preparation. Use this checklist:

### Phase 1: Audit Mode Setup (Week 1)

- [ ] Security workflows deployed in `audit` mode
- [ ] Team has downloaded and reviewed at least one security report
- [ ] Everyone understands how to access reports from workflow artifacts
- [ ] Team has reviewed the common vulnerabilities section in this guide

### Phase 2: Calibration (Weeks 2-4)

- [ ] All existing Critical/High findings are documented in GitHub issues
- [ ] False positives are identified and suppressed (inline comments or .semgrepignore)
- [ ] Team has created a process for triaging new security findings
- [ ] At least one team member knows how to fix each common vulnerability type
- [ ] Architecture.yaml is updated with missing security controls
- [ ] Technical debt backlog is created for non-critical findings

### Phase 3: Pre-Graduation (Week 5)

- [ ] No unreviewed Critical/High findings remain
- [ ] All accepted risks are documented with business justification
- [ ] Security triage meetings are scheduled (weekly or bi-weekly)
- [ ] Team has practiced fixing vulnerabilities in a test branch
- [ ] `SECURITY_MODE: block` tested on a feature branch

### Phase 4: Graduation (Week 6+)

- [ ] Change `SECURITY_MODE` to `block` in `.github/workflows/threat-modeling.yml`
- [ ] Change `SECURITY_MODE` to `block` in `.github/workflows/security-scan.yml`
- [ ] Monitor first 10 PRs to ensure no unexpected build failures
- [ ] Adjust rules/severity mappings if needed
- [ ] Document any remaining exceptions

### Ongoing Maintenance

- [ ] Review security scan results monthly
- [ ] Update `.semgrepignore` as codebase evolves
- [ ] Keep Semgrep rules updated (`config: auto` pulls latest rules)
- [ ] Re-run security scans after major refactoring
- [ ] Review and update accepted risks quarterly

---

## Quick Reference

### Environment Variables

| Variable | Values | Default | Description |
|---|---|---|---|
| `SECURITY_MODE` | `audit`, `block` | `audit` | Fail build on Critical/High findings? |
| `ZHIPU_API_KEY` | (secret) | - | API key for design threat modeling |

### Workflow Files

| File | Purpose |
|---|---|
| `.github/workflows/threat-modeling.yml` | Combined STRIDE + SAST workflow |
| `.github/workflows/security-scan.yml` | SAST-only workflow |
| `.semgrepignore` | SAST exclusion patterns |

### Scripts

| Script | Purpose |
|---|---|
| `scripts/auto_threat_model.py` | Design-level STRIDE threat modeling |
| `scripts/parse_sast_results.py` | Convert Semgrep JSON to XML |
| `scripts/aggregate_security_results.py` | Merge design + code findings |
| `scripts/check_security_severity.py` | Check severity for CI exit code |

### Report Files

| File | Source | Contents |
|---|---|---|
| `threat_report.xml` | STRIDE analysis | Design-level threats |
| `sast_report.xml` | Semgrep scan | Code-level threats |
| `security_report.xml` | Aggregation | Combined threats |

---

## Getting Help

### Questions About Specific Findings

1. Check the **Mitigation** section in the report
2. Review the **References** section (OWASP, CWE links)
3. Search the [Semgrep rules repository](https://github.com/semgrep/semgrep-rules)
4. Ask in team security triage meeting

### Questions About Tool Behavior

- **Design threat modeling issues:** Check `architecture.yaml` accuracy
- **SAST false positives:** Review `.semgrepignore` configuration
- **Build failures:** Check workflow logs for specific error messages

### Escalation Path

1. **Developer:** Attempt fix based on report recommendations
2. **Team Lead:** Review if unsure about severity or fix approach
3. **Security Architect:** Escalate for complex architectural issues
4- **CTO/VP Engineering:** Approve accepted risks with business justification

---

## Best Practices

### Development Workflow

1. **Write code** with security best practices in mind
2. **Commit early** and often - security scans run on every push
3. **Review findings** immediately after scan completes
4. **Fix issues** before requesting PR review
5. **Document exceptions** if accepting risk (with justification)

### Architecture Design

1. **Update architecture.yaml** when adding new components or data flows
2. **Review security controls** section during design phase
3. **Document trust boundaries** explicitly
4. **Include compliance requirements** in security context

### Code Review

1. **Check security scan results** before approving PRs
2. **Verify fixes** address the root cause, not just symptoms
3. **Look for similar vulnerabilities** in other files
4. **Ensure tests cover security scenarios**

---

## Appendix: Vulnerability Coverage

| Vulnerability Type | Design-Level (STRIDE) | Code-Level (Semgrep) | Combined Coverage |
|---|---|---|---|
| SQL Injection | ❌ | ✅ | ✅ |
| Cross-Site Scripting (XSS) | ❌ | ✅ | ✅ |
| Command Injection | ❌ | ✅ | ✅ |
| Hardcoded Secrets | ❌ | ✅ | ✅ |
| IDOR | ⚠️ Partial | ⚠️ Partial | ✅ |
| SSRF | ⚠️ Partial | ✅ | ✅ |
| Authentication Bypass | ⚠️ Partial | ⚠️ Partial | ✅ |
| Missing Encryption | ✅ | ⚠️ Partial | ✅ |
| Insecure Deserialization | ⚠️ Partial | ✅ | ✅ |
| Path Traversal | ❌ | ✅ | ✅ |
| CSRF | ✅ | ⚠️ Partial | ✅ |
| Sensitive Data Exposure | ✅ | ⚠️ Partial | ✅ |
| Security Misconfiguration | ✅ | ✅ | ✅ |
| Broken Access Control | ✅ | ⚠️ Partial | ✅ |
| Cryptographic Failures | ✅ | ✅ | ✅ |

**Legend:**
- ✅ = Full detection capability
- ⚠️ Partial = Limited detection (requires context)
- ❌ = Not detected by this layer

---

*Last Updated: 2026-02-05*

For questions or improvements to this guide, please open an issue or submit a pull request.
