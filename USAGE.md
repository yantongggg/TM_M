# Using TMm_sCaN Across Multiple Repositories

This guide explains how to use the centralized Threat Modeling as Code workflow across multiple repositories.

## 🎯 Overview

The **reusable workflow** approach allows you to:
- Maintain threat modeling logic in ONE place (TMm_sCaN repo)
- Use it across unlimited repositories
- **Auto-discover architecture from code** (no manual setup needed!)
- Update all repos by updating the central workflow
- Keep custom architecture.yaml in each repo (optional)

## 🚀 Two Ways to Use

### Option A: **Auto-Discovery** (Simplest - No Setup Required!)
**Recommended for quick starts** - The system automatically scans your codebase and generates the architecture file.

### Option B: **Manual Architecture** (Best for Accuracy)
**Best for production** - You write the architecture.yaml file for precise control.

---

## 📋 Quick Start - Auto-Discovery (2 Steps!)

This is the **simplest** way to add threat modeling to any repository.

### Step 1: Add the Workflow

Create `.github/workflows/threat-modeling.yml` in your repository:

```yaml
name: Threat Modeling

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master, develop]
  workflow_dispatch:

jobs:
  threat-modeling:
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    with:
      auto_discovery: true  # Enable auto-discovery!
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

### Step 2: Add API Key

Go to: **Settings** → **Secrets and variables** → **Actions** → **New repository secret**
- Name: `ZHIPU_API_KEY`
- Value: Your Zhipu AI API key from https://open.bigmodel.cn/

### That's It!

Push and the workflow will:
1. ✅ Scan your codebase (`package.json`, `requirements.txt`, Docker files, etc.)
2. ✅ Use AI to auto-generate `architecture.yaml`
3. ✅ Perform STRIDE threat modeling
4. ✅ Report results with PR comments

---

## 📋 Manual Setup (3 Steps)

### Step 1: Add Workflow to Your Repository

Create `.github/workflows/threat-modeling.yml` in your repository:

```yaml
name: Threat Modeling

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master, develop]
  workflow_dispatch:

jobs:
  threat-modeling:
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    with:
      architecture_path: 'architecture.yaml'
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

### Step 2: Create Your Architecture Description

Create `architecture.yaml` in your repository root:

```yaml
system:
  name: "My System"
  description: "Description of my system"

components:
  - name: "Web App"
    type: "Web Application"
    technology: "React"
    exposed: true
    trust_zone: "Internet"

  - name: "API"
    type: "API"
    technology: "Python"
    exposed: false
    trust_zone: "Private Network"

data_flows:
  - source: "Web App"
    destination: "API"
    protocol: "HTTPS"
    data_type: "User data"

# See examples/architecture-example.yaml for a complete template
```

### Step 3: Add API Key to Your Repository Secrets

1. Go to your repository on GitHub
2. Navigate to: **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `ZHIPU_API_KEY`
5. Value: Your Zhipu AI API key
6. Click **Add secret**

That's it! Push your changes and the workflow will run automatically.

---

## 🔧 Configuration Options

The reusable workflow accepts these optional parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `auto_discovery` | `true` | Automatically generate architecture.yaml if not found |
| `architecture_path` | `architecture.yaml` | Path to your architecture file |
| `output_path` | `threat_report.xml` | Where to save the report |
| `python_version` | `3.11` | Python version to use |
| `fail_on_high_severity` | `true` | Fail build on Critical/High threats |

### Auto-Discovery Details

When `auto_discovery: true` (default):

1. **First Run** (no `architecture.yaml`):
   - Scans codebase for configuration files
   - Detects: package.json, requirements.txt, Dockerfile, k8s manifests, Terraform, etc.
   - Uses AI to reverse-engineer architecture
   - Generates `architecture.yaml` automatically
   - Performs threat modeling on generated architecture
   - Uploads both as artifacts

2. **Subsequent Runs** (with `architecture.yaml`):
   - Uses existing `architecture.yaml`
   - Skips auto-discovery
   - Runs threat modeling directly

**To disable auto-discovery:**
```yaml
with:
  auto_discovery: false  # Use existing architecture.yaml only
```

### Example with Custom Parameters

```yaml
jobs:
  threat-modeling:
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    with:
      architecture_path: 'docs/architecture.yaml'
      output_path: 'reports/threat-model.xml'
      python_version: '3.12'
      fail_on_high_severity: true
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

---

## 📤 Workflow Outputs

The reusable workflow provides outputs you can use in other jobs:

| Output | Description |
|--------|-------------|
| `threat_count` | Total number of threats found |
| `critical_count` | Number of Critical severity threats |
| `high_count` | Number of High severity threats |
| `has_blocking_threats` | `true` if Critical or High threats exist |
| `architecture_generated` | `true` if architecture was auto-discovered |

### Using Outputs in Your Workflow

```yaml
jobs:
  threat-modeling:
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}

  # This job can access the outputs
  notify-team:
    needs: threat-modeling
    if: ${{ needs.threat-modeling.outputs.has_blocking_threats == 'true' }}
    runs-on: ubuntu-latest
    steps:
      - name: Send notification
        run: |
          echo "⚠️ Blocking threats found!"
          echo "Critical: ${{ needs.threat-modeling.outputs.critical_count }}"
          echo "High: ${{ needs.threat-modeling.outputs.high_count }}"
```

---

## 🏢 Organization-Wide Setup

For GitHub Organizations, you can set up the API key once and share it:

### Option 1: Organization Secrets (Recommended)

1. Go to Organization Settings → Secrets → Actions
2. Create an **Organization secret** named `ZHIPU_API_KEY`
3. Set it as available to specific repositories or all repos
4. Each repository can now use `${{ secrets.ZHIPU_API_KEY }}`

### Option 2: Environment Secrets

For different environments (dev, staging, prod):

```yaml
jobs:
  threat-modeling:
    environment: production  # Uses production secrets
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@master
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

---

## 📁 Repository Structure Examples

### Example 1: Simple Web App

```
my-web-app/
├── .github/
│   └── workflows/
│       └── threat-modeling.yml    # Workflow from Step 1
├── src/
├── architecture.yaml               # Your architecture description
├── package.json
└── README.md
```

### Example 2: Microservices Monorepo

```
my-monorepo/
├── .github/
│   └── workflows/
│       └── threat-modeling.yml
├── services/
│   ├── user-service/
│   ├── payment-service/
│   └── api-gateway/
├── architecture.yaml               # Describe entire system
└── docker-compose.yml
```

### Example 3: Custom Paths

```
my-project/
├── .github/
│   └── workflows/
│       └── threat-modeling.yml
├── docs/
│   └── architecture/
│       └── system-design.yaml      # Custom path
└── threat-modeling.yml             # Updated workflow:
                                      # architecture_path: 'docs/architecture/system-design.yaml'
```

---

## 🔄 Updating All Repositories

When you update the central reusable workflow in TMm_sCaN:

1. **Update TMm_sCaN** repository (the central repo)
2. **All repositories** automatically use the latest version
3. **No changes needed** in individual repositories

If you want to pin to a specific version:

```yaml
jobs:
  threat-modeling:
    # Use a specific tag instead of master
    uses: yantongggg/TMm_sCaN/.github/workflows/threat-modeling-reusable.yml@v1.0.0
    secrets:
      zhipu_api_key: ${{ secrets.ZHIPU_API_KEY }}
```

---

## 🐛 Troubleshooting

### Error: "Architecture file not found"

**Problem:** Workflow can't find your `architecture.yaml`

**Solution:** Check the `architecture_path` parameter matches your file location:
```yaml
with:
  architecture_path: 'architecture.yaml'  # Ensure this path is correct
```

### Error: "ZHIPU_API_KEY not set"

**Problem:** API key secret not configured in your repository

**Solution:** Add the secret in your repository settings:
- Repository → Settings → Secrets → Actions → New repository secret
- Name: `ZHIPU_API_KEY`

### Workflow succeeds but no threats found

**Problem:** Architecture description may be too generic

**Solution:** Add more detail to your `architecture.yaml`:
- Specific technologies and versions
- All data flows with protocols
- External dependencies
- Authentication mechanisms
- Sensitive data handling

---

## 📚 Additional Resources

- **Complete architecture template:** `examples/architecture-example.yaml`
- **Sample workflow:** `examples/workflow-example.yml`
- **Main documentation:** `README.md`
- **Original workflow:** `.github/workflows/threat-modeling-reusable.yml`

---

## 🎓 Best Practices

1. **Keep Architecture Updated**
   - Update `architecture.yaml` when adding new components
   - Review and update quarterly

2. **Be Specific**
   - More detail = better threat analysis
   - Include actual tech stack, protocols, authentication

3. **Review Reports**
   - Don't ignore Medium/Low severity threats
   - Use reports for security awareness

4. **Iterate**
   - Update architecture after implementing mitigations
   - Re-run threat modeling after changes

5. **Share Knowledge**
   - Discuss findings in team meetings
   - Use reports for security training

---

## 🤝 Contributing

Found a bug or have a feature request? Please open an issue at:
https://github.com/yantongggg/TMm_sCaN/issues

---

## 📄 License

MIT License - See LICENSE file for details
