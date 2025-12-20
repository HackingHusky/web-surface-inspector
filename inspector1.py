import requests
from urllib.parse import urlparse
import csv
import re
import json

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
    """
    Convert HTTP headers into real CVE vendor/product pairs
    """
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
    api = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    resp = requests.get(api, timeout=10)

    if resp.status_code != 200:
        print(f"[-] CVE lookup failed for {vendor}/{product}")
        return

    data = resp.json()
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

        collected.append({
            "vendor": vendor,
            "product": product,
            "cve_id": item.get("id", "N/A"),
            "cvss": cvss,
            "summary": item.get("summary", ""),
        })


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
            cf,
            fieldnames=["vendor", "product", "cve_id", "cvss", "summary"]
        )
        writer.writeheader()
        writer.writerows(collected_cves)

    print(f"\n[+] Results saved to {JSON_OUT} and {CSV_OUT}")
else:
    print("\n[+] No CVEs above severity threshold")

# --- Prompt Injection Scan ---
print("\n--- Prompt Injection Scan ---")
patterns = [
    r"ignore previous instructions",
    r"disregard all prior rules",
    r"system override",
    r"bypass safety",
    r"act as",
    r"jailbreak",
]

html = r.text.lower()
found = False

for p in patterns:
    if re.search(p, html):
        print(f"[!] Possible injection phrase: {p}")
        found = True

if not found:
    print("[+] No obvious prompt-injection patterns detected")
