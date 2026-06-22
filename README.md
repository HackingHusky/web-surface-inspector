# Web Surface Inspector
<img width="1376" height="768" alt="image" src="https://github.com/user-attachments/assets/6bada56d-2b40-43f6-a64f-3d6a524b9713" />


An automated web reconnaissance and security auditing utility engineered for target surface analysis. This utility aggregates critical configuration data from a targeted URL, fingerprints remote application stacks, evaluates security defensive layers, and inspects web page bodies for Large Language Model (LLM) prompt-injection patterns.

---

## Technical Capabilities

*   **HTTP Header Inspection:** Enumerates active response headers to catalog remote infrastructure parameters.
*   **Security Header Auditing:** Programmatically evaluates the presence and compliance of defensive headers (e.g., CSP, HSTS, X-Frame-Options).
*   **Application Stack Fingerprinting:** Parses HTML and header hints to determine underlying servers, frameworks, and language runtimes.
*   **Public CVE Enrichment:** Queries public vulnerability registries via the CIRCL API to correlate discovered component versions with historical vulnerabilities.
*   **LLM Prompt-Injection Analysis:** Scans client-side structural content to detect anomalous text strings or instructions optimized to compromise downstream AI integrations.
*   **Isolated Data Triage:** Includes a structured container layer to safely preview remote CSV file content structures.

---

## Installation

Ensure your host environment has Python 3.8 or higher installed before provisioning dependencies.

```bash
# Clone the resource repository
git clone https://github.com
cd web-surface-inspector

# Provision required library dependencies
pip install -r requirements.txt
```

---

## Operational Guide

The utility operates as an interactive command-line interface. 

### Execution Command
```bash
python inspector.py
```

### Usage Workflow
1. Initialize the script within your terminal environment.
2. Provide a fully qualified target URL when prompted:
   ```text
   Enter target URL: https://example.com
   ```

### Operational Output Schema
The tool generates a structured, multi-tier analysis report directly within the terminal interface covering:
*   **Infrastructure Headers:** Passive fingerprinting data.
*   **Defensive Compliance Matrix:** Detailed flags detailing missing protection configurations.
*   **Threat Enrichment:** Publicly documented CVE summaries matching identified technology fingerprints.
*   **AI Input Validation Flags:** Categorized warnings pointing to suspected prompt-injection structural patterns found in the source code.

---

## System Requirements

The application depends on the external third-party components listed within the local configuration manifest:
```text
# requirements.txt
requests>=2.25.0
beautifulsoup4>=4.9.0
```

---

## Regulatory Compliance & Legal Mandate

This application is strictly engineered as administrative scaffolding for authorized vulnerability lifecycle management, security posture validation, and defensive software engineering. This tool does not feature active exploitation capabilities; it functions entirely via passive and structural analysis of publicly exposed data facets. 

Running automated analysis against endpoints without prior, explicit written authorization from the system operator violates local and international computer protection statutes. The authors assume no legal accountability or financial liability for improper configuration or reckless deployment of this tool.

---

## License

This project is open-source software distributed under the terms of the **MIT License**. For complete permission and redistribution terms, refer to the accompanying `LICENSE` file.
