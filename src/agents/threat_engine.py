"""
Three-Agent Threat Modeling Engine

AI-powered threat modeling using a 3-agent pipeline:
1. Architect Agent: Analyzes system context and trust boundaries
2. Attacker Agent: Applies STRIDE methodology to generate threats
3. Validator Agent: Filters false positives and prioritizes findings
"""

import json
import yaml
from typing import Dict, List, Any
from openai import OpenAI


class ThreeAgentThreatEngine:
    """
    AI-powered threat modeling with 3-agent architecture.

    Uses three specialized LLM agents to:
    1. Understand the system architecture (Architect)
    2. Generate STRIDE threats (Attacker)
    3. Validate and prioritize (Validator)
    """

    def __init__(self, api_key: str, base_url: str = "https://open.bigmodel.cn/api/paas/v4"):
        """
        Initialize the threat engine.

        Args:
            api_key: Zhipu AI API key
            base_url: Base URL for the API
        """
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = "glm-4-plus"

    def run_full_pipeline(self, architecture: Dict) -> List[Dict]:
        """
        Run the complete 3-agent threat modeling pipeline.

        Args:
            architecture: System architecture dictionary

        Returns:
            List of validated threat dictionaries
        """
        print("    [Agent 1/3] Architect: Analyzing system context...")
        context = self.analyze_with_architect(architecture)

        print("    [Agent 2/3] Attacker: Generating STRIDE threats...")
        raw_threats = self.analyze_with_attacker(context)

        print("    [Agent 3/3] Validator: Validating and prioritizing...")
        validated_threats = self.validate_with_validator(raw_threats)

        return validated_threats

    def analyze_with_architect(self, architecture: Dict) -> Dict:
        """
        Agent 1: Architect - Analyzes system context.

        Identifies:
        - Trust boundaries
        - Data flow patterns
        - Security-relevant components
        - Attack surface area

        Args:
            architecture: System architecture dictionary

        Returns:
            Context analysis dictionary
        """
        system_prompt = """You are a Senior Security Architect with 20+ years of experience.
Your task is to analyze system architectures and identify security-relevant context.

Analyze the provided architecture and output a JSON document with:
{
  "system_name": "Name of the system",
  "trust_boundaries": ["List of trust boundaries"],
  "data_flows": ["List of critical data flows"],
  "attack_surface": ["List of externally exposed components"],
  "security_context": {
    "handles_pii": boolean,
    "processes_payments": boolean,
    "compliance_requirements": ["List of applicable regulations"]
  }
}

Output ONLY valid JSON. No markdown, no code blocks."""

        user_prompt = f"""Analyze this system architecture:

```yaml
{yaml.dump(architecture, default_flow_style=False)}
```

Provide the security context analysis as JSON."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=2048
            )

            content = response.choices[0].message.content.strip()

            # Clean JSON response
            if content.startswith("```json"):
                content = content[7:]
            elif content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            return json.loads(content)

        except Exception as e:
            print(f"    ⚠️  Architect agent error: {e}")
            return {"system_name": "Unknown", "trust_boundaries": [], "data_flows": []}

    def analyze_with_attacker(self, context: Dict) -> List[Dict]:
        """
        Agent 2: Attacker - Applies STRIDE methodology.

        Generates potential threats using STRIDE:
        - Spoofing
        - Tampering
        - Repudiation
        - Information Disclosure
        - Denial of Service
        - Elevation of Privilege

        Args:
            context: Context analysis from Architect agent

        Returns:
            List of raw threat dictionaries
        """
        system_prompt = """You are an expert Ethical Hacker and Security Researcher.
Your task is to identify potential security threats using the STRIDE methodology.

For each identified threat, provide:
{
  "id": "THREAT-XXX",
  "title": "Threat title",
  "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
  "severity": "Critical|High|Medium|Low",
  "component": "Affected component",
  "description": "Detailed vulnerability description",
  "attack_scenario": "Step-by-step attack scenario",
  "impact": "Technical and business impact",
  "likelihood": "Low|Medium|High",
  "mitigation": "Specific mitigation strategies",
  "references": ["Relevant security standards or CWE IDs"]
}

Output ONLY a valid JSON array of threat objects. No markdown, no code blocks."""

        user_prompt = f"""Based on this security context:

```json
{json.dumps(context, indent=2)}
```

Generate a comprehensive list of STRIDE threats as a JSON array."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.4,
                max_tokens=6144
            )

            content = response.choices[0].message.content.strip()

            # Clean JSON response
            if content.startswith("```json"):
                content = content[7:]
            elif content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            threats = json.loads(content)

            # Ensure it's a list
            if isinstance(threats, dict):
                threats = [threats]

            return threats

        except Exception as e:
            print(f"    ⚠️  Attacker agent error: {e}")
            return []

    def validate_with_validator(self, threats: List[Dict]) -> List[Dict]:
        """
        Agent 3: Validator - Filters false positives and prioritizes.

        Validates each threat for:
        - Exploitability (is this realistically exploitable?)
        - Impact (does this matter?)
        - False positives (is this a theoretical concern?)
        - Priority (how should this be addressed?)

        Args:
            threats: List of raw threats from Attacker agent

        Returns:
            List of validated and prioritized threats
        """
        if not threats:
            return []

        system_prompt = """You are a Senior Security Engineer reviewing threat findings.
Your task is to validate threats and filter out false positives.

For each threat, assess:
1. **Exploitability**: Can this realistically be exploited?
2. **Impact**: Does this have meaningful security impact?
3. **False Positive**: Is this a theoretical concern with no practical risk?

Validated threats should have a "confidence" score (0-100) and "priority" ranking.
Remove threats that are clear false positives or have confidence < 40.

Output format: JSON array with the same threat structure, adding:
{
  ...
  "confidence": 0-100,
  "priority": "P1|P2|P3|P4"
}

Output ONLY a valid JSON array. No markdown, no code blocks."""

        user_prompt = f"""Review and validate these threats:

```json
{json.dumps(threats, indent=2)}
```

Return the validated threats as a JSON array, removing false positives."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=6144
            )

            content = response.choices[0].message.content.strip()

            # Clean JSON response
            if content.startswith("```json"):
                content = content[7:]
            elif content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            validated = json.loads(content)

            # Ensure it's a list
            if isinstance(validated, dict):
                validated = [validated]

            return validated

        except Exception as e:
            print(f"    ⚠️  Validator agent error: {e}")
            # Return original threats if validation fails
            return threats

    def load_architecture(self, yaml_path: str) -> Dict:
        """
        Load architecture from YAML file.

        Args:
            yaml_path: Path to architecture.yaml

        Returns:
            Parsed architecture dictionary
        """
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Failed to load architecture: {e}")
