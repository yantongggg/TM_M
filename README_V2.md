# TM_M v2.0: Repo-First Intelligent Security Orchestration

**Automated Threat Modeling & Security Test Generation with AI**

TM_M is a comprehensive security tool that automatically detects repository types, performs AI-powered STRIDE threat modeling, and generates executable security test code.

## 🎯 Key Features

- **🔍 Automatic Tech Stack Detection**: Detects Flutter (mobile), JavaScript/TypeScript (web), and Python/Go/Java (backend) repositories
- **🤖 3-Agent AI Pipeline**: Uses specialized AI agents for context analysis, threat generation, and validation
- **🧪 Test Code Generation**: Automatically generates Playwright, Flutter, and API fuzzing tests
- **📊 SARIF Reports**: Generates SARIF v2.1.0 reports for GitHub Security tab integration
- **⏱️ Timestamped Reports**: Enforced timestamping for historical tracking
- **🚀 CLI-Driven**: Easy-to-use command-line interface and GitHub Actions integration

## 📋 Prerequisites

- Python 3.11+
- Zhipu AI API key (get one at https://open.bigmodel.cn/)
- Git repository to analyze

## 🚀 Quick Start

### 1. Installation

```bash
# Clone TM_M
git clone https://github.com/yantongggg/TM_M.git
cd TM_M

# Install dependencies
pip install -r requirements.txt
```

### 2. Set API Key

```bash
# Set your Zhipu AI API key
export ZHIPU_API_KEY="your-api-key-here"
```

### 3. Run TM_M

```bash
# Analyze current directory
python src/main.py

# Analyze specific repository
python src/main.py --repo-path /path/to/repo

# Generate security tests
python src/main.py --generate-tests

# Specify output directory
python src/main.py --output-dir my_reports
```

## 📂 Architecture

```
TM_M/
├── src/
│   ├── main.py                 # CLI entry point
│   ├── utils/
│   │   ├── detection.py        # Tech stack detection
│   │   ├── timestamp.py        # Timestamp helpers
│   │   └── config.py           # Configuration management
│   ├── scanners/
│   │   ├── base_scanner.py     # Abstract base class
│   │   ├── mobile_scanner.py   # Flutter/Dart analysis
│   │   ├── web_scanner.py      # JavaScript/TypeScript analysis
│   │   └── backend_scanner.py  # Python/Go/Java analysis
│   ├── agents/
│   │   └── threat_engine.py    # 3-agent AI system
│   └── generators/
│       ├── test_gen.py         # Base test generator
│       ├── playwright_gen.py   # Web security tests
│       ├── flutter_gen.py      # Mobile security tests
│       ├── fuzzing_gen.py      # API fuzzing tests
│       └── report_gen.py       # Markdown + SARIF reports
├── templates/
│   └── sarif_template.json     # SARIF v2.1.0 template
├── action.yml                  # GitHub Actions metadata
├── tm_m_config.yaml            # Default configuration
└── requirements.txt            # Python dependencies
```

## 🔧 Configuration

Create a `tm_m_config.yaml` file in your project:

```yaml
api:
  provider: zhipu
  model: "glm-4-plus"
  temperature: 0.3

output:
  directory: tm_m_reports
  formats:
    - markdown
    - sarif
  include_tests: true

reporting:
  severity_threshold: medium
```

## 🧪 Supported Repository Types

### Mobile (Flutter)
- Detects: `pubspec.yaml`, `.dart` files
- Generates: Flutter integration tests
- Scans: HTTP calls, data storage, platform channels

### Web (JavaScript/TypeScript)
- Detects: `package.json`, `.js`/`.ts`/`.tsx` files
- Frameworks: React, Vue, Angular, Next.js, Express, NestJS
- Generates: Playwright security tests
- Scans: XSS vectors, localStorage, fetch calls, cookies

### Backend (Python/Go/Java)
- Detects: `requirements.txt`, `go.mod`, `pom.xml`
- Frameworks: Django, Flask, FastAPI, Go, Java/Spring
- Generates: API fuzzing tests (pytest)
- Scans: SQL queries, file operations, crypto usage

## 📊 Generated Artifacts

### 1. Markdown Report
Human-readable report with:
- Executive summary with severity breakdown
- Detailed threat descriptions
- Attack scenarios and impact analysis
- Mitigation strategies

### 2. SARIF Report
Machine-readable SARIF v2.1.0 report for:
- GitHub Security tab integration
- CI/CD pipeline integration
- Security audit trails

### 3. Security Tests
Executable test code:
- **Web**: Playwright `.spec.ts` tests (XSS, injection, auth)
- **Mobile**: Flutter `_test.dart` tests (data leaks, integrity)
- **Backend**: Python fuzzing tests (SQL injection, DoS, auth bypass)

## 🔌 GitHub Actions Integration

### Using the Action

Create `.github/workflows/threat-modeling.yml`:

```yaml
name: Security Threat Modeling

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  threat-modeling:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run TM_M
        uses: yantongggg/TM_M@v2
        with:
          api-key: ${{ secrets.ZHIPU_API_KEY }}
          generate-tests: 'true'
          output-dir: tm_m_reports
```

### Upload to Code Scanning

The action automatically uploads SARIF reports to GitHub Security tab:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tm_m_reports/*.sarif
```

## 🎨 CLI Usage

```bash
# Basic usage
python src/main.py

# With all options
python src/main.py \
  --repo-path /path/to/project \
  --api-key YOUR_API_KEY \
  --generate-tests \
  --output-dir security_reports \
  --config custom_config.yaml

# Skip SARIF generation
python src/main.py --no-sarif
```

## 📈 Output Example

```
╭───────────────────────────────────────────────────╮
│ TM_M: Repo-First Intelligent Security Orchestration│
│ Automated Threat Modeling & Security Test Generation│
│                                                       │
│ Version 2.0.0 | https://github.com/yantongggg/TM_M  │
╰───────────────────────────────────────────────────╯

Analyzing: /path/to/repo
Output: tm_m_reports

Step 1: Detecting technology stack...
  ✓ MOBILE_FLUTTER
  ✓ BACKEND_API

Step 2: Scanning repository...
  ✓ Found 12 components
  ✓ Found 45 dependencies

Step 3: Performing AI threat modeling...
  ✓ Found 8 threats

Step 4: Generating security tests...
  ✓ Generated 8 tests

Step 5: Generating reports...
  ✓ SARIF report: tm_m_reports/security_scan_20250106_120000.sarif
  ✓ Markdown report: tm_m_reports/threat_model_20250106_120000.md

┏━━━━━━━━━━━━━━━━━━━━┓
┃ Threats Detected   ┃
┡━━━━━━━━━━━━━━━━━━━━┩
│ Severity │ Count   │
├──────────┼─────────┤
│ 🔴 Critical │ 1     │
│ 🟠 High     │ 2     │
│ 🟡 Medium   │ 4     │
│ 🟢 Low      │ 1     │
└──────────┴─────────┘
```

## 🔐 Security Best Practices

TM_M generates security tests that verify:

1. **Input Validation**: XSS, SQL injection, command injection
2. **Authentication**: JWT security, session management
3. **Authorization**: Privilege escalation prevention
4. **Data Protection**: Secure storage, encryption
5. **Communication**: TLS/SSL, certificate pinning
6. **Mobile Security**: Biometric auth, root detection

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines.

## 📝 License

MIT License - see LICENSE file for details

## 🔗 Links

- [GitHub Repository](https://github.com/yantongggg/TM_M)
- [Documentation](https://github.com/yantongggg/TM_M/wiki)
- [Issue Tracker](https://github.com/yantongggg/TM_M/issues)

## 🙏 Acknowledgments

Built with:
- [Zhipu AI GLM-4](https://open.bigmodel.cn/) - AI threat modeling
- [Playwright](https://playwright.dev/) - Web security testing
- [Flutter](https://flutter.dev/) - Mobile security testing
- [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) - Report format
