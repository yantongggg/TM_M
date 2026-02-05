#!/usr/bin/env python3
"""
Automated STRIDE Threat Modeling Script

This script reads an architecture.yaml file describing a system's components,
data flows, and trust boundaries, then uses the Zhipu AI API to perform
automated threat modeling using the STRIDE methodology.

The script generates an XML threat report and exits with code 1 if any
Critical or High severity threats are detected (to break the CI/CD build).
"""

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any
import yaml
from openai import OpenAI


class ThreatModelingEngine:
    """Main engine for automated threat modeling using Zhipu AI."""

    def __init__(self, api_key: str, base_url: str = "https://open.bigmodel.cn/api/paas/v4"):
        """
        Initialize the threat modeling engine.

        Args:
            api_key: Zhipu AI API key
            base_url: Base URL for the API
        """
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self.system_prompt = self._build_system_prompt()

    def _build_system_prompt(self) -> str:
        """
        Build the system prompt for the LLM.

        Returns:
            System prompt string
        """
        return """You are a senior Security Architect and Threat Modeling expert with 20+ years of experience in cybersecurity. Your expertise includes:

- STRIDE threat modeling methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Security assessments for web applications, microservices, and cloud architectures
- Industry security standards: OWASP Top 10, PCI DSS, GDPR, SOC 2
- Common vulnerability patterns: CWE, CVE, and attack vectors

## Your Task:
Analyze the provided system architecture YAML description and identify potential security threats using the STRIDE methodology.

## Analysis Approach:
1. **Review each component** for vulnerabilities based on its type, technology, and exposure
2. **Analyze each data flow** for security risks in transit
3. **Evaluate trust boundaries** for potential boundary violations
4. **Consider compliance requirements** listed in the security context
5. **Prioritize threats** by impact and likelihood

## Output Requirements:
You MUST output a valid XML document with the following structure. NO markdown formatting, NO code blocks, NO additional text - ONLY pure XML:

```xml
<ThreatModel>
  <Summary>
    <SystemName>[system name]</SystemName>
    <AnalysisDate>[current date]</AnalysisDate>
    <TotalThreats>[count]</TotalThreats>
    <CriticalCount>[count]</CriticalCount>
    <HighCount>[count]</HighCount>
    <MediumCount>[count]</MediumCount>
    <LowCount>[count]</LowCount>
    <Overview>[brief 2-3 sentence summary of the security posture]</Overview>
  </Summary>
  <Threats>
    <Threat category="[Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege]" severity="[Critical|High|Medium|Low]">
      <Title>[Clear, descriptive threat title]</Title>
      <Component>[Affected component(s)]</Component>
      <Description>
        [Detailed description of the threat including:
        - What vulnerability exists
        - How it could be exploited
        - What the impact would be
        - Why this threat applies to this specific architecture]
      </Description>
      <AttackScenario>[Step-by-step scenario of how an attacker could exploit this]</AttackScenario>
      <Impact>[Technical and business impact]</Impact>
      <Likelihood>[Low|Medium|High] with justification</Likelihood>
      <Mitigation>
        [Specific, actionable mitigation strategies including:
        - Technical controls (code changes, configurations)
        - Process changes
        - Security best practices to implement]
      </Mitigation>
      <References>[Relevant OWASP, CWE, or security standards if applicable]</References>
    </Threat>
    <!-- Repeat for each identified threat -->
  </Threats>
</ThreatModel>
```

## Threat Severity Guidelines:
- **Critical**: Direct path to data breach, critical system compromise, or severe compliance violation (e.g., PCI DSS scope)
- **High**: Significant security impact with realistic exploit path
- **Medium**: Moderate impact or lower likelihood exploits
- **Low**: Minor issues or theoretical threats with low likelihood

## Quality Standards:
- Be specific and actionable - avoid generic advice
- Reference the actual components, data flows, and technologies from the YAML
- Consider the specific security context and compliance requirements provided
- Prioritize findings by real-world risk, not theoretical possibilities
- Provide concrete mitigation strategies, not just "implement security"

Remember: Output ONLY the raw XML. Do NOT wrap it in markdown code blocks. Do NOT add explanatory text."""

    def load_architecture(self, yaml_path: str) -> Dict[str, Any]:
        """
        Load the architecture YAML file.

        Args:
            yaml_path: Path to the architecture.yaml file

        Returns:
            Parsed YAML content as dictionary
        """
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Error: Architecture file not found: {yaml_path}", file=sys.stderr)
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error: Failed to parse YAML: {e}", file=sys.stderr)
            sys.exit(1)

    def perform_threat_modeling(self, architecture: Dict[str, Any]) -> str:
        """
        Perform threat modeling using the Zhipu AI API.

        Args:
            architecture: Parsed architecture dictionary

        Returns:
            XML threat report as string
        """
        # Convert architecture to YAML string for the prompt
        architecture_yaml = yaml.dump(architecture, default_flow_style=False, allow_unicode=True)

        user_prompt = f"""Please analyze the following system architecture and provide a comprehensive STRIDE threat model:

```yaml
{architecture_yaml}
```

Generate the complete XML threat model following the specified format."""

        try:
            response = self.client.chat.completions.create(
                model="glm-4",  # Using GLM-4 model; alternatives: glm-4-plus, glm-4-air
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,  # Lower temperature for more consistent, focused output
                max_tokens=8192,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Error calling Zhipu AI API: {e}", file=sys.stderr)
            sys.exit(1)

    def clean_xml_response(self, raw_response: str) -> str:
        """
        Clean the API response to extract pure XML.

        Sometimes LLMs wrap XML in markdown code blocks. This function extracts the raw XML.

        Args:
            raw_response: Raw response from the API

        Returns:
            Clean XML string
        """
        # Remove markdown code blocks if present
        response = raw_response.strip()

        # Remove ```xml and ``` markers
        if response.startswith("```xml"):
            response = response[6:]
        elif response.startswith("```"):
            response = response[3:]

        if response.endswith("```"):
            response = response[:-3]

        return response.strip()

    def parse_threat_report(self, xml_content: str) -> ET.ElementTree:
        """
        Parse the XML threat report.

        Args:
            xml_content: XML content as string

        Returns:
            Parsed XML ElementTree
        """
        try:
            cleaned_xml = self.clean_xml_response(xml_content)
            return ET.fromstring(cleaned_xml)
        except ET.ParseError as e:
            print(f"Error: Failed to parse XML response: {e}", file=sys.stderr)
            print("\n--- Raw Response ---", file=sys.stderr)
            print(xml_content, file=sys.stderr)
            print("--- End Response ---\n", file=sys.stderr)
            sys.exit(1)

    def save_report(self, xml_content: str, output_path: str):
        """
        Save the XML threat report to a file.

        Args:
            xml_content: XML content as string
            output_path: Path to save the report
        """
        try:
            cleaned_xml = self.clean_xml_response(xml_content)
            # Pretty print the XML
            root = ET.fromstring(cleaned_xml)
            ET.indent(root, space="  ")

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write(ET.tostring(root, encoding='unicode'))

            print(f"Threat report saved to: {output_path}")
        except Exception as e:
            print(f"Error saving report: {e}", file=sys.stderr)
            sys.exit(1)

    def check_severity(self, root: ET.Element) -> bool:
        """
        Check if any Critical or High severity threats exist.

        Args:
            root: XML root element

        Returns:
            True if Critical or High threats found (should fail build)
        """
        threats_element = root.find('Threats')
        if threats_element is None:
            return False

        critical_threats = []
        high_threats = []

        for threat in threats_element.findall('Threat'):
            severity = threat.get('severity', '')
            title_elem = threat.find('Title')
            title = title_elem.text if title_elem is not None else "Unknown"

            if severity == 'Critical':
                critical_threats.append(title)
            elif severity == 'High':
                high_threats.append(title)

        # Print summary
        print("\n" + "=" * 60)
        print("THREAT MODELING SUMMARY")
        print("=" * 60)

        summary = root.find('Summary')
        if summary is not None:
            for child in summary:
                if child.text:
                    print(f"{child.tag}: {child.text}")

        print("\n" + "-" * 60)
        if critical_threats:
            print(f"\n⚠️  CRITICAL THREATS DETECTED ({len(critical_threats)}):")
            for i, threat in enumerate(critical_threats, 1):
                print(f"  {i}. {threat}")

        if high_threats:
            print(f"\n⚠️  HIGH SEVERITY THREATS DETECTED ({len(high_threats)}):")
            for i, threat in enumerate(high_threats, 1):
                print(f"  {i}. {threat}")

        if critical_threats or high_threats:
            print("\n" + "=" * 60)
            print("❌ BUILD FAILED: Critical or High severity threats found!")
            print("=" * 60)
            print("\nPlease review the threat_report.xml file and address the identified issues.")
            return True
        else:
            print("\n" + "=" * 60)
            print("✅ BUILD PASSED: No Critical or High severity threats")
            print("=" * 60)
            return False

    def run(self, architecture_path: str, output_path: str):
        """
        Run the complete threat modeling pipeline.

        Args:
            architecture_path: Path to architecture.yaml
            output_path: Path to save threat_report.xml
        """
        print("=" * 60)
        print("AUTOMATED STRIDE THREAT MODELING")
        print("=" * 60)
        print(f"Architecture file: {architecture_path}")
        print(f"Output file: {output_path}")
        print("=" * 60)

        # Step 1: Load architecture
        print("\n[1/4] Loading architecture description...")
        architecture = self.load_architecture(architecture_path)
        print(f"      System: {architecture.get('system', {}).get('name', 'Unknown')}")
        print(f"      Components: {len(architecture.get('components', []))}")
        print(f"      Data flows: {len(architecture.get('data_flows', []))}")

        # Step 2: Perform threat modeling
        print("\n[2/4] Performing STRIDE threat modeling via Zhipu AI...")
        xml_report = self.perform_threat_modeling(architecture)

        # Step 3: Parse and validate XML
        print("\n[3/4] Parsing and validating threat report...")
        root = self.parse_threat_report(xml_report)
        print("      XML validation: ✓ PASSED")

        # Step 4: Save report
        print("\n[4/4] Saving threat report...")
        self.save_report(xml_report, output_path)

        # Check severity and exit accordingly
        should_fail = self.check_severity(root)
        sys.exit(1 if should_fail else 0)


def main():
    """Main entry point for the threat modeling script."""
    # Get configuration from environment variables
    api_key = os.environ.get('ZHIPU_API_KEY')
    if not api_key:
        print("Error: ZHIPU_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    # File paths
    script_dir = Path(__file__).parent.parent
    architecture_path = os.environ.get('ARCHITECTURE_FILE',
                                      str(script_dir / 'architecture.yaml'))
    output_path = os.environ.get('OUTPUT_FILE',
                                 str(script_dir / 'threat_report.xml'))

    # Run threat modeling
    engine = ThreatModelingEngine(api_key=api_key)
    engine.run(architecture_path, output_path)


if __name__ == '__main__':
    main()
