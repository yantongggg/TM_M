#!/usr/bin/env python3
"""
Automatic Architecture Discovery Script

This script scans a codebase to automatically generate an architecture.yaml file
by analyzing the repository structure, configuration files, and infrastructure code.

It uses Zhipu AI to reverse-engineer the system architecture from the codebase.
"""

import os
import sys
from pathlib import Path
from typing import List, Set, Tuple
from openai import OpenAI


# Directories to ignore during scanning
IGNORE_DIRS = {
    'node_modules', '__pycache__', '.git', '.idea', '.vscode',
    'venv', 'env', 'dist', 'build', 'target', 'bin', 'obj',
    '.venv', '.env', 'coverage', '.pytest_cache', '.next',
    '.nuxt', 'vendor', 'bower_components'
}

# Important files to read for architecture inference
IMPORTANT_FILES = {
    # Package managers
    'package.json', 'requirements.txt', 'Pipfile', 'poetry.lock', 'Gemfile',
    'go.mod', 'Cargo.toml', 'composer.json', 'pom.xml', 'build.gradle',

    # Docker/Container
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'docker-compose.dev.yml',

    # Kubernetes/Infrastructure
    'k8s-deployment.yaml', 'kubernetes.yaml', 'helm values', 'terraform',

    # Web servers/Proxies
    'nginx.conf', 'apache.conf', '.htaccess', 'Caddyfile',

    # Databases
    'schema.sql', 'migrations', 'prisma', 'sequelize',

    # API/Backend config
    'app.yaml', 'vercel.json', 'netlify.toml', 'firebase.json',

    # Build tools
    'webpack.config.js', 'vite.config.js', 'tsconfig.json', '.babelrc',
    'next.config.js', 'nuxt.config.js',

    # CI/CD
    '.github', 'Jenkinsfile', '.gitlab-ci.yml', 'azure-pipelines.yml',

    # Environment/Config
    '.env.example', 'config.yml', 'settings.py', 'application.properties',
}


def get_file_tree(startpath: str, max_depth: int = 4) -> str:
    """
    Generate a hierarchical tree view of the directory structure.

    Args:
        startpath: Root directory to scan
        max_depth: Maximum depth to traverse

    Returns:
        String representation of the file tree
    """
    tree_str = ""
    startpath = os.path.abspath(startpath)

    for root, dirs, files in os.walk(startpath):
        # Filter out ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        # Calculate depth
        rel_path = os.path.relpath(root, startpath)
        if rel_path == '.':
            level = 0
        else:
            level = rel_path.count(os.sep)

        # Stop if we've gone too deep
        if level > max_depth:
            dirs[:] = []  # Don't traverse deeper
            continue

        # Build indentation
        indent = '  ' * level
        subindent = '  ' * (level + 1)

        # Add directory
        dirname = os.path.basename(root)
        if level == 0:
            tree_str += f'{dirname}/\n'
        else:
            tree_str += f'{indent}{dirname}/\n'

        # Add files (limit output for readability)
        file_count = 0
        for f in sorted(files):
            if f in IMPORTANT_FILES or f.endswith(('.tf', '.yml', '.yaml', '.json', '.toml')):
                tree_str += f'{subindent}{f}\n'
                file_count += 1
                if file_count >= 10:  # Limit files per directory
                    remaining = len([f for f in files if f not in IGNORE_DIRS]) - file_count
                    if remaining > 0:
                        tree_str += f'{subindent}... and {remaining} more files\n'
                    break

    return tree_str


def get_important_file_contents(startpath: str, max_files: int = 30) -> str:
    """
    Read contents of important configuration and infrastructure files.

    Args:
        startpath: Root directory to scan
        max_files: Maximum number of files to read (to prevent token overflow)

    Returns:
        String containing file contents with headers
    """
    content_str = ""
    files_read = 0

    for root, dirs, files in os.walk(startpath):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for f in files:
            if files_read >= max_files:
                return content_str

            # Check if file is important
            is_important = (
                f in IMPORTANT_FILES or
                f.endswith(('.tf', '.tfvars')) or  # Terraform
                f.endswith(('.yml', '.yaml')) or   # YAML configs
                f == 'Dockerfile' or
                f.endswith('.dockerfile')
            )

            if is_important:
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as file_obj:
                        # Read first 100 lines to keep tokens manageable
                        lines = []
                        for i, line in enumerate(file_obj):
                            if i >= 100:
                                break
                            lines.append(line)

                        content = ''.join(lines)
                        # Truncate very long files
                        if len(content) > 3000:
                            content = content[:3000] + '\n... (truncated)'

                        rel_path = os.path.relpath(path, startpath)
                        content_str += f"\n{'='*60}\n"
                        content_str += f"FILE: {rel_path}\n"
                        content_str += f"{'='*60}\n"
                        content_str += content + "\n"
                        files_read += 1

                except Exception as e:
                    print(f"⚠️  Skipping {f}: {e}", file=sys.stderr)

    return content_str


def detect_project_info(startpath: str) -> dict:
    """
    Detect basic project information from common files.

    Args:
        startpath: Root directory to scan

    Returns:
        Dictionary with project metadata
    """
    info = {
        'name': None,
        'language': None,
        'framework': None,
        'has_docker': False,
        'has_kubernetes': False,
        'has_terraform': False,
        'has_ci': False
    }

    # Check for package.json
    package_json = os.path.join(startpath, 'package.json')
    if os.path.exists(package_json):
        try:
            import json
            with open(package_json, 'r') as f:
                data = json.load(f)
                info['name'] = data.get('name')
                info['language'] = 'JavaScript/TypeScript'
                deps = data.get('dependencies', {}) or data.get('devDependencies', {})
                if 'react' in deps:
                    info['framework'] = 'React'
                elif 'next' in deps:
                    info['framework'] = 'Next.js'
                elif 'vue' in deps:
                    info['framework'] = 'Vue.js'
                elif 'angular' in deps:
                    info['framework'] = 'Angular'
                elif 'express' in deps:
                    info['framework'] = 'Express.js'
                elif 'nestjs' in deps:
                    info['framework'] = 'NestJS'
        except:
            pass

    # Check for requirements.txt
    if os.path.exists(os.path.join(startpath, 'requirements.txt')):
        info['language'] = 'Python'
        try:
            with open(os.path.join(startpath, 'requirements.txt'), 'r') as f:
                content = f.read().lower()
                if 'django' in content:
                    info['framework'] = 'Django'
                elif 'flask' in content:
                    info['framework'] = 'Flask'
                elif 'fastapi' in content:
                    info['framework'] = 'FastAPI'
        except:
            pass

    # Check for Docker
    for dockerfile in ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml']:
        if os.path.exists(os.path.join(startpath, dockerfile)):
            info['has_docker'] = True
            break

    # Check for Kubernetes
    for root, dirs, files in os.walk(startpath):
        if any(f.endswith(('.yml', '.yaml')) and 'k8s' in f.lower() for f in files):
            info['has_kubernetes'] = True
            break

    # Check for Terraform
    for root, dirs, files in os.walk(startpath):
        if any(f.endswith('.tf') for f in files):
            info['has_terraform'] = True
            break

    # Check for CI/CD
    github_actions = os.path.join(startpath, '.github', 'workflows')
    if os.path.exists(github_actions):
        info['has_ci'] = True

    return info


def generate_architecture_yaml(api_key: str, startpath: str = ".", output_path: str = "architecture.yaml"):
    """
    Generate architecture.yaml by scanning the codebase and using AI.

    Args:
        api_key: Zhipu AI API key
        startpath: Root directory to scan
        output_path: Where to save the generated YAML
    """
    client = OpenAI(
        api_key=api_key,
        base_url="https://open.bigmodel.cn/api/paas/v4"
    )

    print("="*60)
    print("🔍 Auto-Discovering Architecture from Codebase")
    print("="*60)

    # Detect project info
    print("\n[1/4] Detecting project information...")
    project_info = detect_project_info(startpath)
    if project_info['name']:
        print(f"      Project: {project_info['name']}")
    if project_info['framework']:
        print(f"      Framework: {project_info['framework']}")
    print(f"      Language: {project_info['language'] or 'Unknown'}")
    print(f"      Docker: {'✓' if project_info['has_docker'] else '✗'}")
    print(f"      Kubernetes: {'✓' if project_info['has_kubernetes'] else '✗'}")
    print(f"      Terraform: {'✓' if project_info['has_terraform'] else '✗'}")

    # Scan file tree
    print("\n[2/4] Scanning repository structure...")
    file_tree = get_file_tree(startpath, max_depth=4)
    print(f"      Structure scanned ({len(file_tree.splitlines())} lines)")

    # Read important files
    print("\n[3/4] Reading configuration and infrastructure files...")
    file_contents = get_important_file_contents(startpath, max_files=30)
    files_found = file_contents.count('FILE:')
    print(f"      Files read: {files_found}")

    # Build system prompt
    system_prompt = """You are a Senior Software Architect and Security Expert. Your job is to reverse-engineer a comprehensive system architecture from a code repository.

## Your Task
Analyze the provided file tree and configuration file contents, then generate a detailed `architecture.yaml` file suitable for STRIDE threat modeling.

## Analysis Process
1. **Identify Components**: Look for:
   - Frontend frameworks (React, Vue, Angular, Next.js, etc.)
   - Backend frameworks (Express, Django, Flask, FastAPI, Spring Boot, etc.)
   - Databases (PostgreSQL, MySQL, MongoDB, Redis, etc.)
   - Caches and message queues (Redis, RabbitMQ, Kafka, etc.)
   - Infrastructure (Docker, Kubernetes, Terraform)
   - Third-party services (AWS, GCP, Azure services)

2. **Map Data Flows**: Determine how data moves between components:
   - API calls (REST, GraphQL, WebSocket)
   - Database queries
   - Message queue communications
   - External API integrations

3. **Identify Trust Boundaries**:
   - Internet-facing components
   - DMZ/public services
   - Private network services
   - Database tier

4. **Infer Security Context**:
   - Does this handle PII? (likely if it's a user-facing app)
   - Does it process payments? (check for Stripe, PayPal integrations)
   - Compliance requirements (infer from industry/type)

## Output Requirements
Output ONLY valid YAML. No markdown, no code blocks, no explanations.

Use this exact structure:

```yaml
system:
  name: "Inferred System Name"
  description: "1-2 sentence summary of what this system does based on the code"
  version: "1.0.0"

components:
  - name: "Component Name (e.g., Web Frontend)"
    type: "Web Application / API / Database / Cache / etc."
    technology: "Specific technology (e.g., React.js 18, Python 3.11 / FastAPI)"
    description: "What this component does"
    exposed: true  # true if accessible from internet
    trust_zone: "Internet / DMZ / Private Network"

data_flows:
  - source: "Component A"
    destination: "Component B"
    protocol: "HTTPS / HTTP / TCP / etc."
    data_type: "What data is transmitted"
    authentication: "How authentication is handled (JWT, OAuth, mTLS, etc.)"

trust_boundaries:
  - name: "Boundary Name"
    type: "Network Boundary / Data Boundary"
    description: "Description of the boundary"
    controls:
      - "Security control in place (WAF, Firewall, mTLS, etc.)"

security_context:
  compliance_requirements:
    - "Inferred requirements (GDPR, SOC 2, etc. - omit if not applicable)"

  threat_modeling_scope:
    - "What to focus on (web security, API security, data protection, etc.)"

  assumptions:
    - "Reasonable assumptions about infrastructure (e.g., Services run in VPC)"
```

## Quality Standards
- Be specific with technologies (use version numbers if found in configs)
- Infer realistic data flows based on common patterns
- Make reasonable assumptions about security controls (it's OK to note if controls are missing)
- Focus on threats that are relevant to the detected architecture
- If you can't infer something, make a reasonable assumption based on best practices

Remember: Output ONLY the raw YAML. No markdown formatting."""

    # Build user prompt
    user_prompt = f"""## Project Information
- Language: {project_info['language'] or 'Unknown'}
- Framework: {project_info['framework'] or 'Unknown'}
- Containerized: {project_info['has_docker']}
- Orchestration: {'Kubernetes' if project_info['has_kubernetes'] else 'None detected'}
- IaC: {'Terraform' if project_info['has_terraform'] else 'None detected'}

## File Tree
```
{file_tree}
```

## Configuration Files
{file_contents}

## Task
Generate the complete architecture.yaml file now based on this codebase analysis."""

    # Call AI
    print("\n[4/4] Generating architecture.yaml with AI...")
    try:
        response = client.chat.completions.create(
            model="glm-4.5",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,
            max_tokens=4096,
        )
    except Exception as e:
        print(f"\n❌ Error calling Zhipu AI: {e}", file=sys.stderr)
        sys.exit(1)

    # Extract and clean content
    content = response.choices[0].message.content.strip()

    # Remove markdown code blocks if present
    if content.startswith("```yaml"):
        content = content[7:]
    elif content.startswith("```"):
        content = content[3:]

    if content.endswith("```"):
        content = content[:-3]

    content = content.strip()

    # Validate basic YAML structure
    if not content or not content.startswith('system:'):
        print("\n❌ Error: AI did not return valid YAML", file=sys.stderr)
        print(f"Received:\n{content}", file=sys.stderr)
        sys.exit(1)

    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        print(f"\n❌ Error writing architecture.yaml: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "="*60)
    print("✅ Architecture discovery complete!")
    print("="*60)
    print(f"\n📄 Generated: {output_path}")
    print(f"📏 Size: {len(content)} bytes")
    print("\nPreview (first 20 lines):")
    print("-" * 60)
    lines = content.split('\n')[:20]
    print('\n'.join(lines))
    if len(content.split('\n')) > 20:
        print("...")
    print("-" * 60)
    print(f"\n💡 Tip: Review and edit {output_path} to add more details")
    print("   before running threat modeling for best results.")


def main():
    """Main entry point."""
    # Get API key from environment
    api_key = os.environ.get('ZHIPU_API_KEY')
    if not api_key:
        print("❌ Error: ZHIPU_API_KEY environment variable is not set.", file=sys.stderr)
        print("\nSet it with:")
        print("  export ZHIPU_API_KEY='your-api-key'")
        print("  # or on Windows:")
        print("  set ZHIPU_API_KEY=your-api-key")
        sys.exit(1)

    # Get paths from environment or use defaults
    startpath = os.environ.get('SCAN_PATH', '.')
    output_path = os.environ.get('OUTPUT_PATH', 'architecture.yaml')

    # Run generation
    generate_architecture_yaml(api_key, startpath, output_path)


if __name__ == '__main__':
    main()
