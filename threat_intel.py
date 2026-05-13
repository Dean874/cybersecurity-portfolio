import requests
import os
from dotenv import load_dotenv
from datetime import datetime

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

# ─────────────────────────────────────────
# WHAT THIS SCRIPT DOES:
# Takes an IP address, URL, or file hash
# and checks it against VirusTotal's threat
# intelligence database, then prints a clean
# report of the findings.
# ─────────────────────────────────────────

def check_ip(ip):
    """Check an IP address against VirusTotal"""
    print(f"\n🔍 Checking IP: {ip}")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        print(f"  Country:       {data.get('country', 'Unknown')}")
        print(f"  Reputation:    {data.get('reputation', 'N/A')}")
        print(f"  Malicious:     {stats.get('malicious', 0)} vendors flagged this")
        print(f"  Suspicious:    {stats.get('suspicious', 0)} vendors flagged this")
        print(f"  Harmless:      {stats.get('harmless', 0)} vendors flagged this")
        verdict(stats.get("malicious", 0))
    else:
        print(f"  ❌ Error: {response.status_code} - Could not retrieve data")


def check_url(target_url):
    """Check a URL against VirusTotal"""
    print(f"\n🔍 Checking URL: {target_url}")
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        print(f"  Final URL:     {data.get('last_final_url', target_url)}")
        print(f"  Malicious:     {stats.get('malicious', 0)} vendors flagged this")
        print(f"  Suspicious:    {stats.get('suspicious', 0)} vendors flagged this")
        print(f"  Harmless:      {stats.get('harmless', 0)} vendors flagged this")
        verdict(stats.get("malicious", 0))
    else:
        print(f"  ❌ Error: {response.status_code} - Could not retrieve data")


def check_hash(file_hash):
    """Check a file hash against VirusTotal"""
    print(f"\n🔍 Checking Hash: {file_hash}")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        print(f"  File Name:     {data.get('meaningful_name', 'Unknown')}")
        print(f"  File Type:     {data.get('type_description', 'Unknown')}")
        print(f"  Malicious:     {stats.get('malicious', 0)} vendors flagged this")
        print(f"  Suspicious:    {stats.get('suspicious', 0)} vendors flagged this")
        print(f"  Harmless:      {stats.get('harmless', 0)} vendors flagged this")
        verdict(stats.get("malicious", 0))
    else:
        print(f"  ❌ Error: {response.status_code} - Could not retrieve data")


def verdict(malicious_count):
    """Print a verdict based on how many vendors flagged the indicator"""
    print()
    if malicious_count == 0:
        print("  ✅ VERDICT: CLEAN — No vendors flagged this as malicious")
    elif malicious_count <= 3:
        print(f"  ⚠️  VERDICT: SUSPICIOUS — {malicious_count} vendor(s) flagged this")
    else:
        print(f"  🚨 VERDICT: MALICIOUS — {malicious_count} vendors flagged this as malicious")


def save_report(indicators):
    """Save a summary report to a text file"""
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("  THREAT INTELLIGENCE REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Author: Dean Alhassan\n")
        f.write("=" * 50 + "\n\n")
        f.write("Indicators checked:\n")
        for item in indicators:
            f.write(f"  - {item}\n")
        f.write("\nSee terminal output for full results.\n")
    print(f"\n📄 Report saved to: {filename}")


# ─────────────────────────────────────────
# MAIN — Edit the indicators below to check
# different IPs, URLs, or file hashes
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  THREAT INTELLIGENCE SCRIPT")
    print("  Author: Dean Alhassan")
    print("  Powered by: VirusTotal API")
    print("=" * 50)

    # ── Add your indicators here ──
    indicators = {
        "ips":     ["8.8.8.8", "185.220.101.45"],
        "urls":    ["http://malware-traffic-analysis.net"],
        "hashes":  ["44d88612fea8a8f36de82e1278abb02f"]  # EICAR test hash
    }

    for ip in indicators["ips"]:
        check_ip(ip)

    for url in indicators["urls"]:
        check_url(url)

    for h in indicators["hashes"]:
        check_hash(h)

    save_report(
        indicators["ips"] + indicators["urls"] + indicators["hashes"]
    )

    print("\n✅ Done!\n")
    
