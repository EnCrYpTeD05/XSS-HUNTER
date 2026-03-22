<div align="center">

# 🎯 XSS Hunter v2.0

### Automated Reflected XSS Scanner for Bug Bounty Hunters

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-HackerOne%20%7C%20Bugcrowd-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0-purple?style=for-the-badge)

**Created by [EnCrYpTeD05](https://github.com/EnCrYpTeD05)**

*"Hack Smart. Hunt Hard."* 🎯

</div>

---

## 📌 Overview

**XSS Hunter v2.0** is a fully automated, end-to-end **Reflected XSS vulnerability scanner** built specifically for bug bounty hunters. It chains together industry-standard open-source tools into a single seamless pipeline — from subdomain enumeration all the way to confirmed Proof-of-Concept XSS vulnerabilities.

No more manual chaining of tools. No more missed parameters. Just one command.

```bash
python3 xsshunter.py -d target.com
```

---

## ⚙️ Workflow

```
Target Domain
      │
      ▼
┌─────────────────────────┐
│  1. Subfinder            │  →  Subdomain Enumeration
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  2. Active Check         │  →  Filter Live Subdomains (20 Threads)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  3. ParamSpider          │  →  Parameter Discovery (No Timeout)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  4. Smart Filter         │  →  Single Params + Remove login/account URLs
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  5. Deduplication        │  →  Remove Duplicate URLs
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  6. FUZZ → 123           │  →  Dalfox Compatibility Fix
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  7. Dalfox Scan          │  →  Reflected XSS + WAF Evasion
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  8. Extract POCs         │  →  vulnerableurl.txt  🎯
└─────────────────────────┘
```

---

## 🚀 Features

### Core Features
| Feature | Description |
|---|---|
| 🔍 Subdomain Enumeration | Subfinder se automatically subdomains discover karta hai |
| ✅ Active Subdomain Check | 20 parallel threads se sirf live subdomains filter karta hai |
| 🕷️ Parameter Discovery | ParamSpider se URLs + parameters — no timeout, 1 lakh+ parameters handle |
| 🎯 Smart URL Filtering | login/account URLs automatically remove, single params filter |
| 🔄 Duplicate Removal | Duplicate URLs scan se pehle clean |
| 💉 Reflected XSS Scan | Dalfox with `--mining-dom=false` — focused Reflected XSS only |
| 🛡️ WAF Evasion | Built-in `--waf-evasion` — WAF protected sites pe bhi kaam karta hai |
| 📋 Clean Output | WAF spam lines filter — sirf important output screen pe |
| 🎯 POC Extraction | Confirmed vulnerable URLs alag file mein save |

### Stability Features
| Feature | Description |
|---|---|
| 🌐 Internet Auto-Recovery | Disconnect pe wait, reconnect pe automatically resume |
| ⚡ Rate Limit Detection | 429 detect hone pe delay auto-increase + 30s wait |
| 📝 Error Logging | Saari errors timestamped log file mein save |
| 🛑 Graceful Exit | Ctrl+C pe bhi progress save rehti hai |
| 🔄 Auto Resume | Interrupted scan wahan se shuru hota hai jahan ruka tha |

### Usability Features
| Feature | Description |
|---|---|
| 📊 Live Progress Bar | Har step ka real-time status |
| 🔢 ParamSpider Live Counter | Parameters milte jaate hain — real-time count dikhata hai |
| ⚙️ Default + Custom Mode | Dalfox apni settings ya custom flags |
| 💻 Single Command | Poora workflow ek command mein |

---

## 📋 Requirements

### Tools
| Tool | Install Command |
|---|---|
| Python 3 | Pre-installed on Kali Linux |
| Subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| ParamSpider | `pip install paramspider` |
| Dalfox | `go install github.com/hahwul/dalfox/v2@latest` |

### Python Libraries
```bash
pip install requests
```

---

## 🛠️ Installation

```bash
# Clone the repo
git clone https://github.com/EnCrYpTeD05/xss-hunter.git
cd xss-hunter

# Install Python dependencies
pip install requests paramspider

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/hahwul/dalfox/v2@latest
```

---

## 📖 Usage

### Basic Usage (Recommended)
```bash
python3 xsshunter.py -d target.com
```

### Custom Dalfox Settings
```bash
python3 xsshunter.py -d target.com --dalfox-mode custom --workers 5 --delay 500 --timeout 30
```

### All Options
```
  -d, --domain        Target domain (required)
  --threads           Threads for active subdomain check (default: 20)
  --dalfox-mode       'default' or 'custom' (default: default)
  --workers           Dalfox workers in custom mode (default: 5)
  --delay             Dalfox delay in ms (default: 500)
  --timeout           Dalfox timeout in seconds (default: 30)
```

---

## 📂 Output Files

| File | Description |
|---|---|
| `subdomains.txt` | All discovered subdomains |
| `activesubdomains.txt` | Live/active subdomains only |
| `parameters.txt` | All discovered parameters (merged) |
| `singleparam.txt` | Filtered single-parameter URLs |
| `withoutfuzz.txt` | Deduplicated URLs ready for scanning |
| `scan` | Full Dalfox scan output |
| `vulnerableurl.txt` | Confirmed vulnerable URLs 🎯 |
| `xss_hunter_errors_*.log` | Error log file |

---

## 🧹 Cleanup Before New Scan

Always clean up before scanning a new target domain:

```bash
rm -rf results/ parameters.txt singleparam.txt withoutfuzz.txt subdomains.txt activesubdomains.txt scan vulnerableurl.txt scanned_urls.txt pending_urls.txt
```

---

## 📸 Sample Output

```
[*] Starting scan [SID:4][4/64][6.25%] / URL: http://target.com/page.php?id=1
[*] Valid target [ code:200 / size:100 ]
[W] Reflected Payload in HTML: id=><script>alert(1)</script>
[POC][R][GET][inHTML-URL] http://target.com/page.php?id=1%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E
[V] Triggered XSS Payload: id="><IMG SRC=x onpageshow="alert(1)" class=dalfox>
[POC][V][GET][inHTML-URL] http://target.com/page.php?id=1%22%3E%3CIMG+SRC%3Dx...
[*] [duration: 31m][issues: 5] Finish Scan!
```

---

## ⚠️ Legal Disclaimer

This tool is intended **strictly for authorized security testing only:**

- ✅ Bug bounty programs (HackerOne, Bugcrowd)
- ✅ CTF competitions
- ✅ Explicitly authorized penetration testing engagements
- ✅ Your own systems/applications

**Always verify the target is in-scope before testing. Follow the program's rules and terms of service at all times.**

The author is **not responsible** for any misuse or damage caused by this tool. Unauthorized use of this tool against systems you do not have permission to test is illegal and unethical.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 EnCrYpTeD05

---

## 👤 Author

**EnCrYpTeD05** | GitHub: [@EnCrYpTeD05](https://github.com/EnCrYpTeD05)

*"Hack Smart. Hunt Hard."* 🎯

---

⭐ **If this tool helped you find bugs, drop a star on the repo!**
