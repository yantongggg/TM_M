# SAST Security Scanning - Quick Start

## What's New

Your repository now includes **comprehensive security scanning** that combines:
- **Design-level threat modeling** (STRIDE methodology)
- **Code-level static analysis** (Semgrep SAST)

## Quick Reference

### Workflows

| File | Purpose | Triggers |
|---|---|---|
| `.github/workflows/threat-modeling.yml` | Combined STRIDE + SAST | Push/PR to main/master/develop |
| `.github/workflows/security-scan.yml` | SAST-only scan | Push/PR to main/master/develop |

### Scripts

| Script | Purpose |
|---|---|
| `scripts/parse_sast_results.py` | Convert Semgrep JSON to XML |
| `scripts/aggregate_security_results.py` | Merge design + code findings |
| `scripts/check_security_severity.py` | Check severity for CI exit code |

### Reports Generated

| Report | Contents |
|---|---|
| `security-report-{n}` | Unified report (design + code) |
| `threat-report-{n}` | Design-level threats only |
| `sast-report-{n}` | Code-level threats only |

### Operating Modes

| Mode | Behavior | When to Use |
|---|---|---|
| `audit` (default) | Reports only, never fails build | Initial deployment (weeks 1-4) |
| `block` | Fails build on Critical/High findings | After graduation (week 5+) |

## Common Vulnerabilities Detected

| Vulnerability | Example | Severity |
|---|---|---|
| SQL Injection | `f"SELECT * FROM users WHERE id = {user_id}"` | High |
| XSS | `<h1>Hello, {username}</h1>` | High |
| Command Injection | `os.system(f"ping {hostname}")` | High |
| Hardcoded Secrets | `API_KEY = "sk_live_abc..."` | Critical |
| Weak Crypto | `hashlib.md5(password)` | Medium |

## How to Fix Findings

### 1. SQL Injection

**Vulnerable:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Fixed:**
```python
query = "SELECT * FROM users WHERE id = %s"
db.execute(query, (user_id,))
```

### 2. XSS

**Vulnerable:**
```javascript
res.send(`<h1>Hello, ${username}</h1>`);
```

**Fixed:**
```javascript
const sanitizeHtml = require('sanitize-html');
res.send(`<h1>Hello, ${sanitizeHtml(username)}</h1>`);
```

### 3. Hardcoded Secrets

**Vulnerable:**
```python
API_KEY = "sk_live_abc123"
```

**Fixed:**
```python
import os
API_KEY = os.environ.get('API_KEY')
```

## Suppressing False Positives

### Method 1: Inline Comment (Semgrep)

```python
# nosemgrep: python.sql-injection
# Reason: User input validated earlier in function
query = f"SELECT * FROM table WHERE id = {user_id}"
```

### Method 2: File Exclusion

Add to `.semgrepignore`:
```
**/test_vulnerabilities.py
**/safe_file.py
```

## Configuration

### Change Operating Mode

Edit `.github/workflows/threat-modeling.yml`:

```yaml
env:
  SECURITY_MODE: block  # Change from 'audit' to 'block'
```

Edit `.github/workflows/security-scan.yml`:

```yaml
env:
  SECURITY_MODE: block  # Change from 'audit' to 'block'
```

## Testing

### Test SAST Detection

```bash
# Create test branch
git checkout -b test/sast

# Temporarily modify .semgrepignore (remove example exclusion)
git add .github/workflows/
git commit -m "test: Security scanning"
git push origin test/sast

# Check workflow results in Actions tab
```

## Accessing Reports

1. Go to **Actions** tab in GitHub
2. Click on latest workflow run
3. Scroll to **Artifacts** section
4. Download report:
   - `security-report-{n}` (recommended - unified)
   - `threat-report-{n}` (design only)
   - `sast-report-{n}` (code only)

## Understanding Severity

| Level | Description | Action Required |
|---|---|---|
| 🔴 **Critical** | Data breach, critical compromise | Fix immediately |
| 🟠 **High** | Realistic exploit path | Fix before production |
| 🟡 **Medium** | Moderate impact | Fix next sprint |
| 🟢 **Low** | Minor/theoretical | Fix when possible |

## Graduation Checklist

Transition from `audit` to `block` mode when:

- [ ] All existing findings documented in GitHub issues
- [ ] False positives identified and suppressed
- [ ] Team has security triage process
- [ ] At least one member can fix each common vulnerability
- [ ] Tested on feature branch with `block` mode
- [ ] Management approval for enforcement

## Getting Help

| Need | Resource |
|---|---|
| Understand reports | `SECURITY_SCAN_README.md` |
| Fix vulnerabilities | `SECURITY_SCAN_README.md` - "How to Fix Findings" |
| Test examples | `examples/vulnerable_code/` |
| Implementation details | `IMPLEMENTATION_SUMMARY.md` |
| General questions | Team security lead/architect |

## Performance

| Operation | Time |
|---|---|
| SAST scan (Semgrep) | 30-60 seconds |
| Threat modeling (STRIDE) | 1-2 minutes |
| Aggregation | < 10 seconds |
| **Total (parallel)** | **~2-3 minutes** |

## Cost

| Tool | Cost |
|---|---|
| Semgrep (SAST) | Free |
| Zhipu AI (threat modeling) | Per API call |
| GitHub Actions | Free tier available |
| **Total** | **$0 additional** |

## What's Next?

1. **Week 1**: Test workflows, review initial findings
2. **Weeks 2-4**: Calibration, suppress false positives, team training
3. **Week 5+**: Graduate to `block` mode, enforce security standards

---

**For detailed information, see [SECURITY_SCAN_README.md](SECURITY_SCAN_README.md)**
