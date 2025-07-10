
#!/usr/bin/env python3
"""
===============================================================================
Script: openssh_shodan_enrich.py
Description: Queries Shodan for SSH services, extracts OpenSSH version
from service banners, normalizes versions, matches against
locally stored CVEs (from `openssh_cvss.json`), and enriches
each Shodan result with applicable CVE IDs.

Prerequisites: - A valid Shodan API key
- Local CVE database from CVE script (openssh_cvss.json)
Output: - JSON file with enriched Shodan results (openssh_shodan.json)
===============================================================================
"""

import json
import re
import pandas as pd
from shodan import Shodan
from packaging.version import parse as parse_version

# === CONFIGURATION ===
API_KEY = "GpnamXFzmDwkU8md6VEgtye2UlJC4NR4" # Replace with your own key
OUTPUT_FILE = "openssh_shodan.json"
CVE_FILE = "openssh_cvss.json"
QUERY = "ssh port:22"
LIMIT = 1000

# === INITIALISE SHODAN API ===
api = Shodan(API_KEY)
shodan_data = []
counter = 0

# === STEP 1: DOWNLOAD SHODAN RESULTS ===

print(f"[+] Starting Shodan search for query: '{QUERY}' (limit={LIMIT})")

for banner in api.search_cursor(QUERY):
    entry = {
        "ip": banner.get('ip_str'),
        "hostnames": banner.get('hostnames'),
        "org": banner.get('org'),
        "data": banner.get('data')
    }
    shodan_data.append(entry)

# Show a preview of the first few entries only
    if counter < 5:
        print(json.dumps(entry, indent=2))

    counter += 1
    if counter >= LIMIT:
        break


print(f"\n[+] Download complete: {counter} results collected. Proceeding to CVE enrichment...\n")

# === STEP 2: LOAD CVE DATABASE FROM LOCAL FILE ===
with open(CVE_FILE, 'r') as f:
    cve_data = json.load(f)

# === STEP 3: HELPER – Extract OpenSSH version from banner ===
def extract_openssh_version(banner):
    """
    Parses the OpenSSH version string from a given SSH banner.
    Example: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8" → "7.2p2"
    """
    match = re.search(r'OpenSSH[_/](\d+\.\d+p?\d*)', banner)
    return match.group(1) if match else None

# === STEP 4: HELPER – Normalize OpenSSH versions like '7.2p2' → '7.2.2' ===
def normalize_openssh_version(raw_version):
    """
    Converts OpenSSH versions like '8.9p1' or '7.2p2' to '8.9.1', '7.2.2'
    so they can be parsed by packaging.version.parse().
    """
    match = re.match(r'^(\d+)\.(\d+)(p\d+)?$', raw_version)
    if not match:
        return None
    major, minor, patch = match.groups()
    patch = patch.replace('p', '.') if patch else '.0'
    return f"{major}.{minor}{patch}"

# === STEP 5: HELPER – Match OpenSSH version to known CVEs ===
def find_matching_cves(version_str, cve_data):
    """
    Compares a version string against CVE fixed_version fields
    and returns a list of applicable CVE IDs.
    """
    if version_str is None:
        return []

    normalized = normalize_openssh_version(version_str)
    if normalized is None:
        return []
    version = parse_version(normalized)
    matched_cves = []

    for entry in cve_data:
        for release in entry.get("releases", []):
            fixed_version_str = release.get("fixed_version")
            if not fixed_version_str or fixed_version_str == "0":
                continue

            fixed_version_clean = re.sub(r'^\d+:', '', fixed_version_str)
            fixed_version_core = re.split(r'[-+]', fixed_version_clean)[0]
            fixed_version_norm = normalize_openssh_version(fixed_version_core)

            if fixed_version_norm is None:
                continue

            fixed_version = parse_version(fixed_version_norm)

            if version < fixed_version:
                matched_cves.append(entry['id'])
                break # Stop checking other releases for this CVE
    return matched_cves

# === STEP 6: ENRICH SHODAN DATA WITH VERSION + MATCHED CVEs ===
for entry in shodan_data:
    banner = entry.get('data', '')
    version = extract_openssh_version(banner)
    entry['openssh_version'] = version
    entry['cves'] = find_matching_cves(version, cve_data)

print(f"[+] CVE enrichment complete. Writing results to {OUTPUT_FILE}")

# === STEP 7: SAVE TO FILE ===
with open(OUTPUT_FILE, 'w') as f:
    json.dump(shodan_data, f, indent=2)

# === PLACEHOLDERS FOR FUTURE STEPS ===
# Upload the CVEs
# Matching & labelling data from two databases
# Extract features & model training

print("[+] Done.")