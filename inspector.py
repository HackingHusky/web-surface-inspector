import requests
from urllib.parse import urlparse
import csv
import re


# Ask user for URL
user_url = input("Please enter a URL: ")
print(f"You entered the following URL: {user_url}")

# Send GET request
r = requests.get(user_url)

print("Fetched URL:", r.url)
print("Status Code:", r.status_code)

# Extract domain
parsed = urlparse(user_url)
domain = parsed.netloc.replace("www.", "")
print("Domain:", domain)

# --- CSV inspection ---
if user_url.endswith(".csv"):
    print("\nCSV file detected — inspecting contents...\n")

    decoded = r.content.decode("utf-8").splitlines()
    reader = csv.reader(decoded)

    for row in reader:
        print(row)
else:
    print("\nNo CSV file detected at this URL.")

# --- Basic fingerprinting ---
print("\nInspecting server headers...")

headers = r.headers
for key, value in headers.items():
    print(f"{key}: {value}")

# Try to detect technologies
tech = []

server = headers.get("Server", "")
powered = headers.get("X-Powered-By", "")

if server:
    tech.append(server)
if powered:
    tech.append(powered)

print("\nDetected Technologies:")
if tech:
    for t in tech:
        print("-", t)
else:
    print("No obvious technologies detected.")

# --- Security Header Audit ---
print("\nSecurity Header Audit:")

security_headers = {
    "Content-Security-Policy": "CSP helps prevent XSS and data injection attacks.",
    "Strict-Transport-Security": "HSTS enforces HTTPS and prevents downgrade attacks.",
    "X-Frame-Options": "Prevents clickjacking.",
    "X-Content-Type-Options": "Prevents MIME sniffing.",
    "Referrer-Policy": "Controls referrer information leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
}

for header, description in security_headers.items():
    if header in headers:
        print(f"[+] {header} present — good ({description})")
    else:
        print(f"[-] {header} missing — potential issue ({description})")

# --- CVE lookup based on detected tech ---
print("\nChecking for CVEs related to detected technologies...\n")

def lookup_cve(vendor, product):
    api = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    resp = requests.get(api, timeout=10)

    if resp.status_code != 200:
        print(f"Failed to query CVEs for {vendor}/{product}")
        return

    data = resp.json()
    results = data.get("results", [])

    # FIX: results can be dict OR list
    if isinstance(results, dict):
        results = list(results.values())

    if not isinstance(results, list) or len(results) == 0:
        print(f"Found 0 CVEs for {vendor}/{product}\n")
        return

    print(f"Found {len(results)} CVEs for {vendor}/{product}")

    for item in results[:5]:
        cve_id = item.get("id", "N/A")
        summary = item.get("summary", "No description available")
        print(f"- {cve_id}: {summary}")

    print()

for t in tech:
    # safer normalization
    t_clean = re.split(r"[ /]", t.lower())[0]
    lookup_cve(t_clean, t_clean)

# --- AI Prompt Injection Detection ---
print("\nScanning page for possible AI prompt-injection patterns...\n")

html = r.text

prompt_injection_patterns = [
    r"ignore previous instructions",
    r"disregard all prior rules",
    r"you are now",
    r"system override",
    r"bypass safety",
    r"act as",
    r"jailbreak",
    r"pretend to be",
    r"override your programming",
    r"this is a test of your alignment",
    r"whats the password?",
]

found = False

for pattern in prompt_injection_patterns:
    if re.search(pattern, html, re.IGNORECASE):
        print(f"[!] Possible prompt-injection phrase detected: '{pattern}'")
        found = True

if not found:
    print("No obvious prompt-injection patterns detected.")
