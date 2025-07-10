import json
import pandas as pd
from shodan import Shodan
import re
import CVE
API_KEY = "GpnamXFzmDwkU8md6VEgtye2UlJC4NR4"
api = Shodan(API_KEY)
OUTPUT_FILE = "openssh_shodan.json"
limit = 1000
counter = 0

def extract_openssh_version(banner):
    match = re.search(r'OpenSSH[_/](\d+\.\d+\w*)', banner)
    return match.group(1) if match else None
#download data from shodan
shodan_data = []
for banner in api.search_cursor('ssh port:22'):
    entry = {
        "ip": banner.get('ip_str'),
        "hostnames": banner.get('hostnames'),
        "org": banner.get('org'),
        "data": banner.get('data')
    }
    shodan_data.append(entry)
    print(json.dumps(entry, indent=2))
    counter += 1
    if counter >= limit:
        break
with open(OUTPUT_FILE, 'w') as f:
    json.dump(shodan_data, f, indent=2)
#upload the CVEs

#matching &labeling data from two databases

#extract features&model training



