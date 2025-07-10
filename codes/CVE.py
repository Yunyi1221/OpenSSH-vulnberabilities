import requests
import json

# This is the URL of Debian's public security data in JSON format.
DEBIAN_API = "https://security-tracker.debian.org/tracker/data/json"

# This is the package we're interested in (we're only looking at OpenSSH).
PACKAGE = "openssh"

# This is the name of the file where we will save the output.
OUTPUT_FILE = "openssh_cvss.json"

# This function connects to Debian's server and downloads the entire CVE dataset.
def fetch_debian_data():
    # Print a message so the user knows what we’re doing
    print(f"Fetching Debian CVE data for '{PACKAGE}'...")

    # Make an HTTP GET request to the API
    response = requests.get(DEBIAN_API)

    # If the server doesn’t respond with status code 200 (OK), we stop with an error
    if response.status_code != 200:
        raise Exception(f"Failed to fetch data: {response.status_code}")

    # If we get here, it means everything went fine. Now we return the JSON data.
    return response.json()

    # This function extracts only the CVEs that affect OpenSSH from the large Debian dataset.
def extract_openssh_cves(data):
    # If for some reason the package isn’t in the dataset, raise an error
    if PACKAGE not in data:
        raise Exception(f"Package '{PACKAGE}' not found in Debian tracker")

    # Get the CVE records for OpenSSH (this is a dictionary where keys are CVE IDs)
    cve_data = data[PACKAGE]
    
    # We will collect all useful data into this list
    result = []

    # Loop through each CVE record for OpenSSH
    for cve_id, details in cve_data.items():
    # Create a new dictionary to store information about this specific CVE
        cve_entry = {
            "id": cve_id, # The CVE ID, like CVE-2021-41617
            "description": details.get("description", ""), # Human-readable summary
            "releases": [] # A list to store per-release information (buster, sid, etc.)
            }
    # Loop through all the releases that have information about this CVE
        for release, release_data in details.get("releases", {}).items():
        # Build a dictionary for this release’s status
            version_info = {
                "release": release, # e.g., "buster", "bullseye", "sid"
                "status": release_data.get("status"), # e.g., "fixed", "open", etc.
                "fixed_version": release_data.get("fixed_version"), # version where bug was fixed
                "urgency": release_data.get("urgency") # severity level (low, medium, high)
                }

        # Add this release’s info to the list for this CVE
        cve_entry["releases"].append(version_info)

    # Add the complete CVE entry to our final result list
    result.append(cve_entry)

    # Once all CVEs are processed, return the list
    return result

# This function saves our results to a file in JSON format.
def save_json(data, filename):
    # Open a file with the given name in write mode ('w')
    # The `with` block ensures the file is properly closed when done
    with open(filename, 'w') as f:
    # Write the data to the file using the `json.dump()` function
    # `indent=2` just makes the JSON look nice (pretty-printed)
        print(json.dump(data, f, indent=2))

        # Print a message so the user knows where the data went
        print(f"Saved {len(data)} CVEs to {filename}")

# This block is where everything starts when the script is run
# It ensures this only runs if the file is executed (not imported)
if __name__ == "__main__":
    # Step 1: Download the data from Debian
    debian_data = fetch_debian_data()

    # Step 2: Extract only the OpenSSH CVEs from the giant dataset
    parsed_data = extract_openssh_cves(debian_data)
    
    # Step 3: Save that filtered data to a JSON file on disk
    save_json(parsed_data, OUTPUT_FILE)
