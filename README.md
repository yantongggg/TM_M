# Threat Modeling as Code (TMaC)

Automated STRIDE threat modeling pipeline integrated into CI/CD using Zhipu AI.

## Overview

This project implements a "Threat Modeling as Code" approach that automatically analyzes your system architecture for security threats during the CI/CD pipeline. It uses the **STRIDE methodology** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) powered by Zhipu AI's LLM to identify potential security vulnerabilities.

## Features

- **Automated STRIDE Analysis**: Leverages AI to systematically identify threats across all STRIDE categories
- **CI/CD Integration**: GitHub Actions workflow that runs on every PR and push
- **Build Breaking**: Automatically fails builds when Critical or High severity threats are detected
- **Structured XML Reports**: Generates detailed, machine-readable threat reports
- **YAML-based Architecture**: Simple, declarative format for describing your system
- **PR Comments**: Automatically comments on PRs with threat summary
- **Artifact Storage**: Threat reports stored as workflow artifacts

## Quick Start

### 1. Repository Setup

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

## File Structure

```
.
├── architecture.yaml                          # System architecture description
├── scripts/
│   └── auto_threat_model.py                  # Threat modeling script
├── .github/workflows/
│   └── threat-modeling.yml                   # GitHub Actions workflow
├── requirements.txt                           # Python dependencies
└── threat_report.xml                         # Generated threat report (after CI run)
```

## Components

### architecture.yaml

Describes your system's:
- **Components**: Services, databases, APIs, etc.
- **Data Flows**: How data moves between components
- **Trust Boundaries**: Security zones (Internet, DMZ, Private Network)
- **Security Context**: Compliance requirements, assumptions

### auto_threat_model.py

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

| Severity | Description | Build Behavior |
|----------|-------------|----------------|
| **Critical** | Direct path to data breach or critical compromise | Fails build ❌ |
| **High** | Significant security impact with realistic exploit | Fails build ❌ |
| **Medium** | Moderate impact or lower likelihood | Passes build ⚠️ |
| **Low** | Minor issues or theoretical threats | Passes build ⚠️ |

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

- **GitHub Artifacts**: Download `threat-report-{run_number}` for the full XML
- **PR Comments**: Automatic summary comment on pull requests
- **Job Summary**: Summary available in the workflow run page
- **Build Status**: ❌ Fails if Critical/High threats found

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
5. **False Positives**: If you encounter false positives, refine the architecture description

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
