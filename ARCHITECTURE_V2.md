# TM_M v2.0 Architecture Overview

## System Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER INPUT                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ CLI Command  │  │ GitHub       │  │ Manual       │             │
│  │              │  │ Action       │  │ Execution    │             │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │
│         │                  │                  │                     │
│         └──────────────────┴──────────────────┘                     ││                            │
└─────────────────┬───────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      PHASE 1: DETECTION                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Tech Stack Detection (src/utils/detection.py)                │  │
│  │                                                               │  │
│  │ • MOBILE_FLUTTER  (pubspec.yaml, .dart files)               │  │
│  │ • WEB_FRONTEND   (package.json, .js/.ts files)               │  │
│  │ • BACKEND_API    (requirements.txt, go.mod, pom.xml)         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Security Pattern Detection                                   │  │
│  │                                                               │  │
│  │ • Network calls (HTTP, fetch, axios)                         │  │
│  │ • Data storage (localStorage, SharedPreferences)             │  │
│  │ • XSS vectors (innerHTML, eval)                              │  │
│  │ • Crypto usage (hashlib, crypto/)                            │  │
│  │ • Authentication patterns                                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     PHASE 2: SCANNING                                │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │ MobileScanner  │  │  WebScanner    │  │BackendScanner  │        │
│  │  (Flutter)     │  │ (JS/TS)        │  │ (Py/Go/Java)   │        │
│  │                │  │                │  │                │        │
│  │ • Components   │  │ • Components   │  │ • Components   │        │
│  │ • Dependencies │  │ • Dependencies │  │ • Dependencies │        │
│  │ • Patterns     │  │ • Patterns     │  │ • Patterns     │        │
│  └────────────────┘  └────────────────┘  └────────────────┘        │
│                                                                       │
│  Extracts: Context, Architecture, Components, Data Flows            │
└─────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  PHASE 3: 3-AGENT AI PIPELINE                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ AGENT 1: ARCHITECT                                           │  │
│  │ src/agents/threat_engine.py → analyze_with_architect()       │  │
│  │                                                               │  │
│  │ Task: Analyze system context                                │  │
│  │ Output:                                                       │  │
│  │   { system_name, trust_boundaries, data_flows,               │  │
│  │     attack_surface, security_context }                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                               │                                       │
│                               ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ AGENT 2: ATTACKER                                            │  │
│  │ src/agents/threat_engine.py → analyze_with_attacker()        │  │
│  │                                                               │  │
│  │ Task: Generate STRIDE threats                               │  │
│  │ Methodology:                                                 │  │
│  │   • Spoofing                                                 │  │
│  │   • Tampering                                                │  │
│  │   • Repudiation                                              │  │
│  │   • Information Disclosure                                   │  │
│  │   • Denial of Service                                        │  │
│  │   • Elevation of Privilege                                   │  │
│  │ Output: List of threat dictionaries (JSON)                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                               │                                       │
│                               ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ AGENT 3: VALIDATOR                                           │  │
│  │ src/agents/threat_engine.py → validate_with_validator()      │  │
│  │                                                               │  │
│  │ Task: Filter false positives & prioritize                    │  │
│  │ Assesses:                                                    │  │
│  │   • Exploitability                                          │  │
│  │   • Impact                                                  │  │
│  │   • False positive potential                                │  │
│  │ Output: Validated threats with confidence scores & priority  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 PHASE 4: TEST GENERATION                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ PlaywrightTestGenerator (src/generators/playwright_gen.py)   │  │
│  │                                                               │  │
│  │ Generates: tests/security/*.spec.ts                          │  │
│  │ • XSS injection tests                                        │  │
│  │ • SQL injection tests                                        │  │
│  │ • Data leak tests                                            │  │
│  │ • Authentication/authorization tests                         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ FlutterTestGenerator (src/generators/flutter_gen.py)         │  │
│  │                                                               │  │
│  │ Generates: tests/security/*_test.dart                        │  │
│  │ • Data leak in logs tests                                    │  │
│  │ • Secure storage tests                                       │  │
│  │ • Code integrity tests                                       │  │
│  │ • Biometric authentication tests                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ FuzzingTestGenerator (src/generators/fuzzing_gen.py)         │  │
│  │                                                               │  │
│  │ Generates: tests/security/fuzz_*.py                          │  │
│  │ • SQL injection fuzzing                                      │  │
│  │ • DoS fuzzing (large payloads, rate limiting)                │  │
│  │ • Auth bypass fuzzing                                        │  │
│  │ • Command injection fuzzing                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  PHASE 5: REPORT GENERATION                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ generate_sarif_report() (src/generators/report_gen.py)       │  │
│  │                                                               │  │
│  │ Output: tm_m_reports/security_scan_YYYYMMDD_HHMMSS.sarif    │  │
│  │ • SARIF v2.1.0 format                                        │  │
│  │ • GitHub Security tab integration                            │  │
│  │ • Rule definitions and results                               │  │
│  │ • Attack scenarios, impact, mitigation                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ generate_markdown_report() (src/generators/report_gen.py)    │  │
│  │                                                               │  │
│  │ Output: tm_m_reports/threat_model_YYYYMMDD_HHMMSS.md        │  │
│  │ • Executive summary with severity breakdown                  │  │
│  │ • Detailed threat descriptions                               │  │
│  │ • Attack scenarios and impact                                │  │
│  │ • Mitigation strategies                                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        OUTPUT ARTIFACTS                             │
│                                                                       │
│  1. Security Tests                                                  │
│     └── target_repo/tests/security/                                 │
│         ├── *.spec.ts (Playwright - Web)                            │
│         ├── *_test.dart (Flutter - Mobile)                          │
│         └── fuzz_*.py (pytest - Backend)                            │
│                                                                       │
│  2. SARIF Report                                                    │
│     └── tm_m_reports/security_scan_YYYYMMDD_HHMMSS.sarif           │
│         → Uploads to GitHub Security Tab                            │
│                                                                       │
│  3. Markdown Report                                                 │
│     └── tm_m_reports/threat_model_YYYYMMDD_HHMMSS.md               │
│         → Human-readable security findings                          │
│                                                                       │
│  4. Console Summary                                                 │
│     └── Rich output with tables and emoji indicators                │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. **JSON over XML**
- Better integration with modern tools
- Easier to parse and manipulate
- SARIF natively uses JSON

### 2. **3-Agent Architecture**
- **Separation of Concerns**: Each agent has a specific role
- **Quality**: Validator agent reduces false positives
- **Transparency**: Can inspect each agent's output

### 3. **Modular Scanner Design**
- **Abstract Base Class**: Consistent interface across scanners
- **Extensibility**: Easy to add new platform support
- **Specialization**: Each scanner optimized for its platform

### 4. **Template-Based Test Generation**
- **Consistency**: All tests follow similar structure
- **Maintainability**: Update templates to improve all tests
- **Coverage**: Maps STRIDE categories to test types

### 5. **Timestamped Reporting**
- **Historical Tracking**: Compare reports over time
- **Uniqueness**: No file name conflicts
- **Sorting**: Easy to sort chronologically

## Technology Stack

### Core
- **Python 3.11+**: Main implementation language
- **OpenAI SDK**: AI API integration (Zhipu AI)
- **PyYAML**: Configuration parsing

### Test Generation
- **Playwright**: Web security testing
- **Flutter**: Mobile security testing
- **pytest**: Backend fuzzing tests

### Reporting
- **SARIF v2.1.0**: GitHub Security integration
- **Markdown**: Human-readable reports
- **Rich CLI**: Beautiful console output

## Extension Points

### Adding New Platform Support

1. Create scanner in `src/scanners/`
   ```python
   class NewPlatformScanner(BaseScanner):
       def scan(self) -> Dict:
           # Implementation
   ```

2. Create test generator in `src/generators/`
   ```python
   class NewPlatformTestGenerator(BaseTestGenerator):
       def generate_tests(self) -> List[Path]:
           # Implementation
   ```

3. Update detection logic in `src/utils/detection.py`
   ```python
   def detect_tech_stack(repo_path: str) -> List[str]:
       if (repo_path / "config_file").exists():
           stacks.append("NEW_PLATFORM")
   ```

### Adding New Test Types

1. Add test generation method to generator
2. Map threat category to test type in `generate_tests()`
3. Create test template in `templates/`

### Adding New Report Formats

1. Add format to `src/generators/report_gen.py`
2. Update config in `tm_m_config.yaml`
3. Add CLI flag in `src/main.py`

---

**Version:** 2.0.0
**Last Updated:** February 6, 2025
