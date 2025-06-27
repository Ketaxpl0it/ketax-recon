# 🕵️‍♂️ Recon Framework v1.0

KetaxRecon is a Python-based automated reconnaissance toolkit for bug bounty hunters. It integrates tools like subfinder, httpx, gau, dirsearch, and gf to discover subdomains, find live hosts, crawl URLs, and detect common vulnerabilities in a streamlined workflow.


---

## 🚀 Features

- Subdomain enumeration via Subfinder
- Live host detection using httpx
- Directory fuzzing with Dirsearch
- URL collection via gau (GetAllUrls)
- GF pattern matching (xss, sqli, lfi, ssti, idor)
- Threaded scanning for faster results
- Organized output for each domain target

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

# 📦 Usage

```bash
python3 ketax-recon.py
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
recon/
└── example.com/
    ├── subdomains.txt
    ├── live.txt
    ├── gau.txt
    ├── xss_patterns.txt
    ├── sqli_patterns.txt
    └── dir_<url>.txt
```

# 👨‍💻 Author
Coded with 💻 by Ketaxpl0it (Neel Tundiya).

# ⚠️ Disclaimer
This tool is intended for educational and authorized security testing only. Unauthorized usage may be illegal.
