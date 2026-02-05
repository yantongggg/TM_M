# Threat Modeling as Code (TMaC)

Automated STRIDE threat modeling and SAST security scanning pipeline integrated into CI/CD.

## Overview

This project implements a comprehensive "Security as Code" approach that combines:
- **Design-level threat modeling** using STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **Code-level static analysis** using Semgrep SAST (SQL injection, XSS, command injection, etc.)

Both security layers run in parallel during CI/CD and generate unified security reports.

## Features

- **🤖 Auto-Discovery**: Automatically scans codebase and generates architecture.yaml
- **Automated STRIDE Analysis**: Leverages AI to systematically identify threats across all STRIDE categories
- **🔍 SAST Code Scanning**: Static code analysis using Semgrep for implementation vulnerabilities
- **Unified Security Reports**: Merges design and code findings into single report
- **CI/CD Integration**: GitHub Actions workflow that runs on every PR and push
- **Dual Operating Modes**: Audit mode (non-blocking) and Block mode (fail on Critical/High)
- **Structured XML Reports**: Generates detailed, machine-readable threat reports
- **YAML-based Architecture**: Simple, declarative format for describing your system
- **PR Comments**: Automatically comments on PRs with security summary
- **Artifact Storage**: Security reports stored as workflow artifacts

## 🆕 Security Scanning

This repository now includes comprehensive security scanning with:

- **Semgrep (SAST)**: Static code analysis for SQL injection, XSS, command injection, hardcoded secrets, and more
- **Unified Reports**: Combined design-level and code-level findings in one report
- **Audit/Block Modes**: Start with non-blocking audits, graduate to security enforcement

**📖 Documentation:**
- **[Quick Start Guide](QUICK_START_SAST.md)** - Get started in 5 minutes
- **[Security Scanning Guide](SECURITY_SCAN_README.md)** - Comprehensive documentation (vulnerabilities, fixes, graduation checklist)
- **[Implementation Summary](IMPLEMENTATION_SUMMARY.md)** - Technical details and architecture

## 🚀 Quick Start

### 🌟 New: Auto-Discovery Mode (Simplest!)

**Just add the workflow - no manual setup needed!**

Create `.github/workflows/threat-modeling.yml`:

```yaml
name: Threat Modeling

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master, develop]

jobs:
  threat-modeling:
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

Add `ZHIPU_API_KEY` to repository secrets → Push → Done!

The system will automatically scan your codebase and generate the architecture.

---

### Option A: Manual Setup in This Repository (Standalone)

Add your Zhipu AI API key to your GitHub repository secrets:

```bash
# Navigate to your repository settings
# Settings → Secrets and variables → Actions → New repository secret
# Name: ZHIPU_API_KEY
# Value: your_api_key_here
```

### 2. Describe Your Architecture

Edit `architecture.yaml` to describe your system:

```yaml
system:
  name: "Your System Name"
  description: "System description"

components:
  - name: "Web Frontend"
    type: "Web Application"
    technology: "React.js"
    exposed: true
    trust_zone: "Internet"

data_flows:
  - source: "Web Frontend"
    destination: "API Gateway"
    protocol: "HTTPS"
```

### 3. Commit and Push

```bash
git add architecture.yaml .github/workflows/threat-modeling.yml
git commit -m "Add threat modeling pipeline"
git push
```

The workflow will automatically run and generate a threat report!

### Option B: Use Across Multiple Repositories (Recommended)

Want to use this workflow across multiple repositories? **[→ See USAGE.md](USAGE.md)**

This approach lets you:
- ✅ Maintain threat modeling logic in ONE central place
- ✅ Use it across unlimited repositories
- ✅ Update all repos by updating the central workflow
- ✅ Keep custom `architecture.yaml` in each repo

**Quick setup for other repos:**

```yaml
# In YOUR repository: .github/workflows/threat-modeling.yml
jobs:
  threat-modeling:
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    with:
      architecture_path: 'architecture.yaml'
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

Plus, add an `architecture.yaml` file to describe your system.

**[→ Full instructions in USAGE.md](USAGE.md)**

---

## File Structure

```
.
├── architecture.yaml                          # System architecture description
├── scripts/
│   ├── auto_threat_model.py                  # Main threat modeling script
│   ├── auto_generate_arch.py                 # Auto-discovery script
│   ├── parse_sast_results.py                 # Parse Semgrep results to XML
│   ├── aggregate_security_results.py         # Merge design + code findings
│   └── check_security_severity.py            # Check severity for CI exit code
├── .github/workflows/
│   ├── threat-modeling.yml                   # Combined STRIDE + SAST workflow
│   ├── security-scan.yml                     # SAST-only workflow
│   └── threat-modeling-reusable.yml          # Reusable workflow with auto-discovery
├── examples/
│   ├── workflow-example.yml                  # Example workflow for other repos
│   └── architecture-example.yaml             # Architecture template
├── .semgrepignore                            # SAST exclusion patterns
├── requirements.txt                           # Python dependencies
├── README.md                                  # This file
├── SECURITY_SCAN_README.md                   # Comprehensive security scanning guide
├── USAGE.md                                   # Guide for using across multiple repos
└── (Generated reports)
    ├── threat_report.xml                     # Design-level threats (STRIDE)
    ├── sast_report.xml                       # Code-level threats (Semgrep)
    └── security_report.xml                   # Unified security report
```

## Components

### auto_generate_arch.py (NEW!)

**Auto-discovery script** that reverse-engineers your architecture from code:

- Scans repository for configuration files
- Detects: package.json, requirements.txt, Dockerfile, k8s, Terraform, etc.
- Identifies tech stack and frameworks
- Uses Zhipu AI to generate architecture.yaml
- No manual setup required!

**Usage:**
```bash
export ZHIPU_API_KEY="your_key"
python scripts/auto_generate_arch.py
```

### architecture.yaml

Python script that:
1. Loads and parses `architecture.yaml`
2. Sends the architecture to Zhipu AI with a STRIDE-focused prompt
3. Receives and validates the XML threat report
4. Saves the report to `threat_report.xml`
5. Exits with code 1 if Critical/High threats are found

### threat-modeling.yml

GitHub Actions workflow that:
1. Sets up Python environment
2. Installs dependencies (openai, pyyaml)
3. Runs the threat modeling script
4. Uploads the report as an artifact
5. Comments on PRs with results

## Usage

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set your API key
export ZHIPU_API_KEY="your_api_key_here"

# Run threat modeling
python scripts/auto_threat_model.py
```

### Customization

You can customize the script via environment variables:

```bash
export ARCHITECTURE_FILE="path/to/custom/architecture.yaml"
export OUTPUT_FILE="path/to/custom/report.xml"
export ZHIPU_API_KEY="your_api_key"
python scripts/auto_threat_model.py
```

## Threat Severity Levels

| Severity | Description | Build Behavior (Block Mode) |
|----------|-------------|----------------------------|
| **Critical** | Direct path to data breach or critical compromise | Fails build ❌ |
| **High** | Significant security impact with realistic exploit | Fails build ❌ |
| **Medium** | Moderate impact or lower likelihood | Passes build ⚠️ |
| **Low** | Minor issues or theoretical threats | Passes build ⚠️ |

**Note:** The pipeline can operate in two modes:
- **Audit Mode** (default): Reports findings but never fails the build
- **Block Mode**: Fails build on Critical/High severity findings

See [SECURITY_SCAN_README.md](SECURITY_SCAN_README.md) for details on operating modes.

## Sample Output

The generated XML report includes:

```xml
<ThreatModel>
  <Summary>
    <SystemName>E-Commerce Payment Processing</SystemName>
    <TotalThreats>8</TotalThreats>
    <CriticalCount>2</CriticalCount>
    <HighCount>3</HighCount>
    ...
  </Summary>
  <Threats>
    <Threat category="Tampering" severity="Critical">
      <Title>Payment Data Injection in Payment Service</Title>
      <Description>...</Description>
      <Mitigation>...</Mitigation>
    </Threat>
  </Threats>
</ThreatModel>
```

## CI/CD Integration

### Workflow Triggers

- **Push to main/master/develop**: Runs on every commit
- **Pull Requests**: Runs on every PR to main/master/develop
- **Manual**: Can be triggered manually from GitHub Actions tab

### Results

- **GitHub Artifacts**: Download reports for full details
  - `security-report-{run_number}` - Unified report (design + code)
  - `threat-report-{run_number}` - Design-level threats only
  - `sast-report-{run_number}` - Code-level threats only
- **PR Comments**: Automatic summary comment on pull requests
- **Job Summary**: Summary available in the workflow run page
- **Build Status**: Depends on `SECURITY_MODE` (audit/block)

## Configuration

### Zhipu AI Model Selection

Edit `scripts/auto_threat_model.py:108` to change the model:

```python
model="glm-4-flash",  # Options: glm-4-plus, glm-4-air, glm-4-flash
```

| Model | Speed | Quality | Cost |
|-------|-------|---------|------|
| glm-4-plus | Slower | Best | Higher |
| glm-4-air | Fast | Good | Medium |
| glm-4-flash | Fastest | Good | Lower |

### System Prompt Customization

Modify `_build_system_prompt()` in `auto_threat_model.py` to customize:
- Threat analysis approach
- Severity criteria
- Output format requirements
- Security standards to apply

## Best Practices

1. **Keep Architecture Updated**: Maintain `architecture.yaml` as your system evolves
2. **Review Medium/Low Threats**: Even non-blocking threats should be reviewed
3. **Iterate**: Update architecture and re-run after implementing mitigations
4. **Team Collaboration**: Discuss findings in security reviews
5. **False Positives**: Use `.semgrepignore` or inline comments for code findings
6. **Start in Audit Mode**: Use non-blocking mode initially, graduate to block mode
7. **Document Accepted Risks**: Create GitHub issues for accepted security risks
8. **Fix Implementation Bugs**: Prioritize SAST findings (real vulnerabilities)
9. **Address Design Issues**: Plan architectural improvements for STRIDE threats

**See [SECURITY_SCAN_README.md](SECURITY_SCAN_README.md) for:**
- How to fix common vulnerabilities (SQL injection, XSS, etc.)
- Suppressing false positives
- Graduation checklist from audit to block mode

## Security Considerations

- **API Key Storage**: Always use GitHub Secrets, never commit API keys
- **Report Sensitivity**: Threat reports may contain sensitive information
- **Access Control**: Control who can view workflow artifacts in your org
- **Rate Limits**: Be aware of Zhipu AI API rate limits

## Troubleshooting

### Build fails with "ZHIPU_API_KEY not set"

→ Add the secret in repository settings

### XML parsing error

→ Check the workflow logs for the raw API response. The LLM may have output invalid XML.

### Too many false positives

→ Refine your `architecture.yaml` with more specific details about existing security controls

### API timeout/error

→ Check your Zhipu AI account status and API quota

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.
