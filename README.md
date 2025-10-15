# 🕵️‍♂️ Recon Framework v2.0

KetaxRecon is a Python-based automated reconnaissance toolkit for bug bounty hunters. It integrates tools like subfinder, httpx, gau, dirsearch, and gf to discover subdomains, find live hosts, crawl URLs, and detect common vulnerabilities in a streamlined workflow.


---

## 🚀 Features

| Module | Description |
|--------|--------------|
| **Tool Installation Helper** | Detects missing tools and installs automatically (supports Ubuntu, Kali, Arch, macOS) |
| **Subdomain Enumeration** | Runs Subfinder, Amass, DNSX to collect subdomains |
| **Live Host Detection** | Uses HTTPX to find reachable hosts |
| **Endpoint Discovery** | Collects URLs via GAU and Katana |
| **Pattern Scanning** | Detects common vulnerability patterns using GF |
| **Vulnerability Scanning** | Runs Nuclei templates for known issues |
| **AI Analysis (Gemini)** | Analyzes endpoints and JavaScript files for potential vulnerabilities |
| **Report Generation** | Generates JSON summaries and text reports |
| **Email Notifications** | Sends summary reports via SMTP |
| **Batch Mode & Threading** | Supports automated scans and concurrent operations |


---

## 🛠 Tools Used

- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- [dirsearch](https://github.com/maurosoria/dirsearch)
- [gau](https://github.com/lc/gau)
- [gf](https://github.com/tomnomnom/gf)

---

## 🧱 Requirements


Make sure the following tools are installed and accessible in your PATH:

```bash
subfinder
httpx
dirsearch
gau
gf
xargs
```

install python dependences
```bash
pip install colorama
```

# Configuration
```bash 
python3 ketax-recon.py --create-config

This will create a file named config.json.sample.
Copy it to config.json and fill in your details:

{
  "email": {
    "smtp_server": "smtp.gmail.com",
    "sender_email": "you@example.com",
    "sender_password": "app-password",
    "recipient_email": "recipient@example.com"
  },
  "shodan_api_key": "your-shodan-api-key",
  "gemini_api_key": "your-gemini-api-key"
}
```

# 📦 Usage

### Basic Scan
```bash
python3 ketax-recon.py example.com
```

### Batch Mode (for automation)
```bash
python3 ketax-recon.py example.com --batch --threads 100 --config config.json
```

### Helper Commands
```bash
python3 ketax-recon.py --install-deps     # Install Python dependencies
python3 ketax-recon.py --create-config    # Generate sample config
```
Enter your target domain when prompted. Output will be saved inside:
```bash
./recon/<target-domain>/
```

# 🧪 Sample Workflow

1.Subdomain Enumeration
2.Live Host Detection
3.Directory Bruteforcing
4.URL Harvesting
5.Vulnerability Pattern Matching

# 📁 Output Structure
```md
./recon/example.com/
├── subfinder.txt
├── amass.txt
├── dnsx.txt
├── final_subdomains.txt
├── targets.txt
├── gau.txt
├── katana.txt
├── combined_urls.txt
├── gf_xss.txt
├── nuclei_results.txt
├── gemini_analysis.json
├── js_analysis.json
├── prioritized_findings.json
└── summary.txt
```

# 👨‍💻 Author
Coded with 💻 by Ketaxpl0it (Neel Tundiya).

# ⚠️ Disclaimer
This tool is intended for educational and authorized security testing only. Unauthorized usage may be illegal.
