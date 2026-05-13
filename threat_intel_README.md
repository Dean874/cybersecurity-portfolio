# Python Threat Intelligence Script

**Author:** Dean Alhassan  
**Language:** Python 3  
**API:** VirusTotal v3  
**Type:** Security Automation / Threat Intelligence

---

## What This Project Does

This Python script takes suspicious indicators — IP addresses, URLs, and file hashes — and automatically checks them against **VirusTotal's threat intelligence database**, which aggregates results from 70+ antivirus and security vendors.

It then produces a clean, readable verdict for each indicator and saves a summary report to a `.txt` file.

---

## Why This Matters (Real World Context)

In a Security Operations Centre (SOC), analysts regularly need to triage suspicious indicators quickly. Manually checking each one on VirusTotal's website is slow and doesn't scale. This script automates that process — the same way real threat intelligence platforms do — allowing an analyst to check multiple indicators in seconds and get a consistent, documented output.

---

## What It Checks

| Indicator Type | Example |
|---|---|
| **IP Address** | `185.220.101.45` |
| **URL** | `http://suspicious-site.com` |
| **File Hash (MD5/SHA256)** | `44d88612fea8a8f36de82e1278abb02f` |

---

## Sample Output

```
==================================================
  THREAT INTELLIGENCE SCRIPT
  Author: Dean Alhassan
  Powered by: VirusTotal API
==================================================

🔍 Checking IP: 8.8.8.8
  Country:       US
  Reputation:    539
  Malicious:     0 vendors flagged this
  Suspicious:    0 vendors flagged this
  Harmless:      56 vendors flagged this

  ✅ VERDICT: CLEAN — No vendors flagged this as malicious

🔍 Checking IP: 185.220.101.45
  Country:       DE
  Reputation:    -21
  Malicious:     16 vendors flagged this
  Suspicious:    4 vendors flagged this
  Harmless:      44 vendors flagged this

  🚨 VERDICT: MALICIOUS — 16 vendors flagged this as malicious

🔍 Checking Hash: 44d88612fea8a8f36de82e1278abb02f
  File Name:     eicar
  File Type:     Powershell
  Malicious:     66 vendors flagged this
  Suspicious:    0 vendors flagged this
  Harmless:      0 vendors flagged this

  🚨 VERDICT: MALICIOUS — 66 vendors flagged this as malicious

📄 Report saved to: report_20260513_212913.txt
✅ Done!
```

---

## How to Run It Yourself

### 1. Clone the repo
```bash
git clone https://github.com/Dean874/cybersecurity-portfolio
cd cybersecurity-portfolio
```

### 2. Install dependencies
```bash
pip3 install requests python-dotenv
```

### 3. Get a free VirusTotal API key
- Sign up at [virustotal.com](https://www.virustotal.com)
- Go to your profile → API Key
- Copy your key

### 4. Create a `.env` file
Create a file called `.env` in the same folder and add:
```
VT_API_KEY=your_api_key_here
```

### 5. Add your indicators and run
Open `threat_intel.py` and edit the indicators section:
```python
indicators = {
    "ips":     ["8.8.8.8", "185.220.101.45"],
    "urls":    ["http://suspicious-site.com"],
    "hashes":  ["your_file_hash_here"]
}
```
Then run:
```bash
python3 threat_intel.py
```

---

## Security Note

The `.env` file containing your API key is **never uploaded to GitHub**. It stays on your local machine only. This is standard practice for handling credentials in code.

---

## Skills Demonstrated

- Python scripting and API integration
- RESTful API consumption (VirusTotal v3)
- Secure credential management using `.env`
- Threat intelligence triage and automation
- Security report generation
- Real-world SOC analyst workflow simulation

---

## Tools & Libraries

| Tool | Purpose |
|---|---|
| `requests` | HTTP calls to the VirusTotal API |
| `python-dotenv` | Secure API key loading from `.env` |
| `datetime` | Timestamped report generation |
| VirusTotal API v3 | Threat intelligence data source |
