import argparse
import base64
import datetime
import io
import os
import sys
import zipfile
from pathlib import Path

import requests

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

def fetch_and_save_whoisds(target_date: datetime.date):
    """
    Downloads the daily Newly Registered Domains (NRD) ZIP from WhoisDS,
    extracts the domains, and saves them to a text file.
    """
    date_str = target_date.strftime("%Y-%m-%d")
    zip_filename = f"{date_str}.zip"
    b64_filename = base64.b64encode(zip_filename.encode()).decode()
    url = f"https://whoisds.com/whois-database/newly-registered-domains/{b64_filename}/nrd"

    print(f"[*] Fetching WhoisDS Newly Registered Domains for {date_str}...")
    
    try:
        # Use a real browser user-agent to prevent blocking
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=30)
        
        if resp.status_code == 404:
            print(f"[-] No data available yet for {date_str}.")
            print("    WhoisDS usually publishes the list at the end of the day or a few days later.")
            sys.exit(1)
            
        resp.raise_for_status()
        
        print("[*] Download complete. Extracting ZIP...")
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            # Usually there is only one domain-names.txt file inside
            for filename in z.namelist():
                if filename.endswith(".txt"):
                    content = z.read(filename).decode("utf-8", errors="ignore")
                    domains = [line.strip() for line in content.splitlines() if line.strip()]
                    
                    if not domains:
                        print("[-] ZIP file was empty.")
                        sys.exit(1)
                        
                    output_file = OUTPUT_DIR / f"whoisds_nrd_{date_str}.txt"
                    
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write("\n".join(domains))
                        
                    print(f"[+] Success! Extracted {len(domains):,} domains.")
                    print(f"[+] Saved to: {output_file.absolute()}")
                    return
                    
        print("[-] Could not find a text file inside the downloaded ZIP.")
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error occurred: {e}")
        sys.exit(1)
    except zipfile.BadZipFile:
        print("[-] The downloaded file is not a valid ZIP file.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Download daily WhoisDS NRD ZIP")
    parser.add_argument(
        "--date", "-d",
        type=str,
        help="Target date in YYYY-MM-DD format (default: today)",
    )
    args = parser.parse_args()

    if args.date:
        try:
            target_date = datetime.date.fromisoformat(args.date)
        except ValueError:
            print("[-] Invalid date format. Use YYYY-MM-DD.")
            sys.exit(1)
    else:
        # Use yesterday by default because WhoisDS usually takes a day or two to publish
        target_date = datetime.date.today() - datetime.timedelta(days=1)

    fetch_and_save_whoisds(target_date)

if __name__ == "__main__":
    main()
