# Web Surface Inspector

A lightweight reconnaissance and security-inspection tool for URLs.

This script performs:
- HTTP header inspection
- Basic technology fingerprinting
- Security header auditing
- CSV content preview
- CVE lookups (via CIRCL)
- AI prompt-injection pattern detection

⚠️ Intended for **educational, defensive, and authorized testing only**.

---

## Features

- Detects missing security headers
- Extracts server / framework hints
- Queries public CVE databases
- Flags common prompt-injection strings in HTML
- Inspects CSV files safely

---

## Installation

```bash
git clone [https://github.com/HackingHusky/web-surface-inspector]
cd web-surface-inspector
pip install -r requirements.txt
```

Usage
```bash
python inspector.py
```

Then enter a full URL:

```bash
https://example.com
```

Example Output

Server headers

Technology fingerprints

Security header audit

CVE summaries

Prompt-injection warnings

Legal & Ethical Use

Only scan systems you own or have explicit permission to test.
This tool does not exploit vulnerabilities—it only inspects publicly accessible data.
