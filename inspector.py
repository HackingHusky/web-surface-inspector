import csv
import json
import re
from urllib.parse import urlparse
import requests

# ---------------- CONFIG ----------------
CVSS_THRESHOLD = 7.0
CSV_OUT = "cves.csv"
JSON_OUT = "cves.json"
# ----------------------------------------


def detect_waf_cdn(headers):
    waf_signatures = {
        "cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
        "akamai": ["akamai"],
        "fastly": ["fastly"],
        "aws cloudfront": ["cloudfront"],
        "imperva": ["incapsula", "imperva"],
        "sucuri": ["sucuri"],
        "azure": ["x-azure-ref"],
    }
    detected = []
    header_blob = " ".join(f"{k}:{v}".lower() for k, v in headers.items())
    for waf, indicators in waf_signatures.items():
        if any(i in header_blob for i in indicators):
            detected.append(waf)
    return list(set(detected))


def map_headers_to_cve_targets(headers):
    """Convert HTTP headers into real CVE vendor/product pairs"""
    targets = []
    header_blob = " ".join(f"{k}:{v}".lower() for k, v in headers.items())
    mappings = [
        # Web servers
        (r"apache/?([\d\.]+)?", "apache", "http_server"),
        (r"nginx/?([\d\.]+)?", "nginx", "nginx"),
        (r"lighttpd/?([\d\.]+)?", "lighttpd", "lighttpd"),
        (r"openresty/?([\d\.]+)?", "openresty", "openresty"),
        (r"iis/?([\d\.]+)?", "microsoft", "iis"),
        # TLS / crypto
        (r"openssl/?([\d\.]+)?", "openssl", "openssl"),
        # App runtimes
        (r"php/?([\d\.]+)?", "php", "php"),
        (r"asp\.net", "microsoft", "asp.net"),
        (r"node\.js", "nodejs", "node.js"),
        # Java
        (r"tomcat/?([\d\.]+)?", "apache", "tomcat"),
        (r"jetty/?([\d\.]+)?", "eclipse", "jetty"),
    ]
    for pattern, vendor, product in mappings:
        if re.search(pattern, header_blob):
            targets.append((vendor, product))
    return list(set(targets))


def lookup_cve(vendor, product, collected):
    api = f"https://circl.lu{vendor}/{product}"
    try:
        resp = requests.get(api, timeout=10)
        if resp.status_code != 200:
            print(f"[-] CVE lookup failed for {vendor}/{product}")
            return
        data = resp.json()
    except Exception:
        print(f"[-] Error connecting to CVE API for {vendor}/{product}")
        return

    results = data.get("results", [])
    if isinstance(results, dict):
        results = list(results.values())
    if not isinstance(results, list) or not results:
        print(f"[+] No CVEs found for {vendor}/{product}")
        return

    for item in results:
        cvss = item.get("cvss", 0.0) or 0.0
        if cvss < CVSS_THRESHOLD:
            continue
        collected.append(
            {
                "vendor": vendor,
                "product": product,
                "cve_id": item.get("id", "N/A"),
                "cvss": cvss,
                "summary": item.get("summary", ""),
            }
        )


def scan_ai_vulnerabilities(html_content):
    """Scans for AI leaks, prompt injections, and data poisoning vectors (OWASP LLM03)"""
    findings = []
    html_lower = html_content.lower()

    # 1. Advanced Prompt Injection & Jailbreak Vectors
    injection_categories = {
        "Direct Override": [
            r"ignore (all )?previous instructions",
            r"disregard (all )?prior rules",
            r"system override",
            r"bypass (safety|filters)",
            r"you must now act as",
            r"new persona:",
        ],
        "Indirect / Hidden Attacks": [
            r"font-size:\s*0px",
            r"display:\s*none",
            r"color:\s*transparent",
            r"rgba\(0,0,0,0\)",
        ],
        "Data Exfiltration Frameworks": [
            r"fetch\(['\"].*?exfiltrate",
            r"webhook\.site",
            r"burpcollaborator",
        ],
        "Refusal / Error Emulation": [
            r"instead, output the following error:",
            r"print 'system error'",
            r"simulate a crash",
        ],
    }

    # 2. Training Data Poisoning Vectors (OWASP LLM03)
    poisoning_categories = {
        "Adversarial Backdoors": [
            r"trigger phrase:",
            r"execute command when",
            r"respond with the keyword",
            r"\u200b",  # Zero-width spaces used to skew text encodings
        ],
        "Targeted Label/Fact Poisoning": [
            r"always classify this as",
            r"assume that .*? is false",
            r"overwrite existing knowledge base",
            r"the absolute correct fact is",
        ],
        "Bias & Toxicity Injections": [
            r"hate speech",
            r"discriminatory terminology",
            r"manipulated metric",
        ],
    }

    print("\n--- [AI] Prompt Injection & Logic Scans ---")
    for category, patterns in injection_categories.items():
        for pattern in patterns:
            match = re.search(pattern, html_lower)
            if match:
                finding = f"[!] {category} Pattern Found: '{match.group(0)}'"
                print(finding)
                findings.append({"type": category, "detail": match.group(0)})

    print("\n--- [AI] Training Data Poisoning Scans (OWASP LLM03) ---")
    for category, patterns in poisoning_categories.items():
        for pattern in patterns:
            match = re.search(pattern, html_lower)
            if match:
                finding = f"[!] {category} Vector Detected: '{match.group(0)}'"
                print(finding)
                findings.append({"type": category, "detail": match.group(0)})

    # Out-of-Distribution Data / Gibberish Detection (Basic check for low-entropy/spam blocks)
    # Attackers use large blocks of gibberish text to skew target word distributions
    gibberish_match = re.search(r"[a-z0-9]{50,}", html_lower)
    if gibberish_match:
        finding = f"[!] Suspected High-Entropy Poisoning Stream: '{gibberish_match.group(0)[:30]}...'"
        print(finding)
        findings.append({"type": "Data Poisoning Stream", "detail": "High-entropy text stream"})

    # 3. Defensive Control Evaluation
    print("\n--- [AI] Defensive Control Evaluation ---")
    untrusted_inputs_found = re.findall(
        r"<input|<textarea|<form", html_lower
    )

    if untrusted_inputs_found:
        print(
            f"[*] Found {len(untrusted_inputs_found)} input fields exposed to potential LLM consumption."
        )
        print("[-] Recommendation: Enforce strict data sanitization and output mapping.")
    else:
        print("[+] No raw web-form input structures exposed directly.")

    return findings


# ---------------- MAIN ----------------
user_url = input("Please enter a URL: ").strip()
print(f"You entered: {user_url}")
r = requests.get(user_url, timeout=10)
parsed = urlparse(user_url)
domain = parsed.netloc.replace("www.", "")

print(f"\nDomain: {domain}")
print(f"Status: {r.status_code}")

headers = r.headers
print("\n--- HTTP Headers ---")
for k, v in headers.items():
    print(f"{k}: {v}")

# --- WAF / CDN Detection ---
print("\n--- WAF / CDN Detection ---")
wafs = detect_waf_cdn(headers)
if wafs:
    for w in wafs:
        print(f"[+] Detected: {w}")
else:
    print("[-] No WAF/CDN detected")

# --- Header → CVE Mapping ---
print("\n--- Header → CVE Vendor Mapping ---")
cve_targets = map_headers_to_cve_targets(headers)
if cve_targets:
    for v, p in cve_targets:
        print(f"[+] Mapped: {v}/{p}")
else:
    print("[-] No CVE-mappable technologies detected")

# --- CVE Lookup ---
print(f"\n--- CVE Lookup (CVSS ≥ {CVSS_THRESHOLD}) ---")
collected_cves = []
for vendor, product in cve_targets:
    lookup_cve(vendor, product, collected_cves)

# --- Output Results ---
if collected_cves:
    print(f"\n[+] {len(collected_cves)} high-severity CVEs found\n")
    for c in collected_cves[:10]:
        print(f"{c['cve_id']} | CVSS {c['cvss']} | {c['summary'][:80]}")

    with open(JSON_OUT, "w") as jf:
        json.dump(collected_cves, jf, indent=2)

    with open(CSV_OUT, "w", newline="") as cf:
        writer = csv.DictWriter(
            cf, fieldnames=["vendor", "product", "cve_id", "cvss", "summary"]
        )
        writer.writeheader()
        writer.writerows(collected_cves)
    print(f"\n[+] Results saved to {JSON_OUT} and {CSV_OUT}")
else:
    print("\n[+] No CVEs above severity threshold")

# --- Run Updated AI Module ---
ai_findings = scan_ai_vulnerabilities(r.text)
if not ai_findings:
    print("[+] No obvious prompt-injection or data poisoning patterns detected.")
