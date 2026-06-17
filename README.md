<div align="center">

# 🎯 XSS Hunter v2.0

### Automated Reflected XSS Scanner for Bug Bounty Hunters

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Workflow-red?style=for-the-badge)
![Web UI](https://img.shields.io/badge/Web%20Dashboard-Pink%20%2B%20Cyan-ff2060?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0-purple?style=for-the-badge)

**Created by [EnCrYpTeD05](https://github.com/EnCrYpTeD05)**

*"Hack Smart. Hunt Hard."* 🎯

</div>

---

## 📌 Overview

**XSS Hunter v2.0** is an automated, end-to-end **Reflected XSS vulnerability scanner** built for fast bug bounty workflows.

It chains together trusted tools like **Subfinder**, **ParamSpider**, and **Dalfox** into one smooth pipeline: from subdomain discovery to vulnerable URL extraction.

Now it also includes a full **local web dashboard**:

- Netflix-style animated intro
- Pink + cyan hacker theme
- Live scan logs
- Stop scan
- Resume stopped scan
- Selective output file downloads
- Fresh dashboard state on reopen

CLI users can still run everything from terminal:

```bash
xsshunter -d target.com
```

Web users can launch the dashboard:

```bash
xsshunter --web
```

---

## ⚙️ Workflow

```text
Target Domain
      |
      v
+-------------------------+
|  1. Subfinder           |  ->  Subdomain Enumeration
+-----------+-------------+
            |
            v
+-------------------------+
|  2. Active Check        |  ->  Filter Live Subdomains
+-----------+-------------+
            |
            v
+-------------------------+
|  3. ParamSpider         |  ->  Parameter Discovery
+-----------+-------------+
            |
            v
+-------------------------+
|  4. Smart Filter        |  ->  Single Parameter URLs
+-----------+-------------+
            |
            v
+-------------------------+
|  5. FUZZ Cleanup        |  ->  Replace FUZZ + Remove Duplicates
+-----------+-------------+
            |
            v
+-------------------------+
|  6. Dalfox Scan         |  ->  Reflected XSS + WAF Evasion
+-----------+-------------+
            |
            v
+-------------------------+
|  7. Extract POCs        |  ->  vulnerableurl.txt
+-------------------------+
```

---

## 🚀 Features

### Core Features

| Feature | Description |
|---|---|
| 🔍 Subdomain Enumeration | Discovers subdomains using `subfinder` |
| ✅ Active Subdomain Check | Filters live targets using threaded HTTP checks |
| 🕷️ Parameter Discovery | Collects URLs and parameters using `paramspider` |
| 🎯 Smart URL Filtering | Keeps single-parameter URLs and skips noisy login/account URLs |
| 🔄 Duplicate Removal | Removes duplicate URLs before scanning |
| 💉 Reflected XSS Scan | Runs Dalfox against prepared URL input |
| 🛡️ WAF Evasion | Uses Dalfox WAF evasion flags |
| 📋 Clean Output | Saves each scan stage into separate output files |
| 🎯 POC Extraction | Extracts `[POC]` and `[W]` findings into `vulnerableurl.txt` |

### Web Dashboard Features

| Feature | Description |
|---|---|
| 🎬 Cinematic Intro | Netflix-style `XSS HUNTER` intro animation |
| 🌈 Theme Variant | Alternates red and pink/cyan glassmorphism intro styles |
| 📊 Live Status | Shows `Running`, `Waiting`, `Stopped By User`, and `Scan Finish` |
| 🛑 Stop Scan | Stop the current scan from the web UI |
| 🔁 Resume Scan | Resume a stopped scan from the dashboard |
| 📥 Selective Downloads | Download only the output file you want |
| 🧼 Fresh Reopen | Old scans do not auto-show when dashboard reopens |
| 🖥️ Background Server | `xsshunter --web` starts the server and frees the terminal |

### Stability Features

| Feature | Description |
|---|---|
| 🌐 Internet Auto-Recovery | Waits when internet disconnects and continues after reconnect |
| ⚡ Rate Limit Handling | Detects rate-limit signals and increases delay |
| 📝 Error Logging | Saves timestamped error logs |
| 🛑 Graceful Exit | Saves progress when stopped |
| 🔄 Resume Logic | Skips already-scanned URLs during Dalfox resume flow |

---

## 📋 Requirements

| Tool | Type |
|---|---|
| Python 3 | Runtime |
| Subfinder | Go tool |
| ParamSpider | Python tool |
| Dalfox | Go tool |
| Go | Required for Go-based tools |
| Git + Curl | Setup utilities |

---

## 🛠️ Installation

### Auto Install Recommended

```bash
git clone https://github.com/EnCrYpTeD05/XSS-HUNTER.git
cd XSS-HUNTER
chmod +x install.sh
./install.sh
```

The installer will:

| Step | Action |
|---|---|
| 1 | Install required system packages |
| 2 | Install `subfinder` |
| 3 | Install `dalfox` |
| 4 | Install `paramspider` |
| 5 | Create global `xsshunter` command |
| 6 | Verify required tools |

After install, run from anywhere:

```bash
xsshunter --help
```

### Link Only

If tools are already installed and you only want the global command:

```bash
./install.sh --link-only
```

This creates:

```text
/usr/local/bin/xsshunter
```

---

## 📖 Usage

### Web Dashboard

```bash
xsshunter --web
```

Custom host and port:

```bash
xsshunter --web --host 127.0.0.1 --port 8787
```

### CLI Basic Scan

```bash
xsshunter -d target.com
```

### CLI Custom Dalfox Settings

```bash
xsshunter -d target.com --dalfox-mode custom --workers 5 --delay 500 --timeout 30
```

### Python Direct Run

```bash
python3 xsshunter.py -d target.com
```

```bash
python3 xsshunter.py --web
```

---

## ⚙️ Options

```text
  --web                 Launch local web dashboard
  --host                Web dashboard host (default: 127.0.0.1)
  --port                Web dashboard port (default: 8787)
  -d, --domain          Target domain
  --threads             Active subdomain check threads (default: 20)
  --dalfox-mode         default or custom
  --workers             Dalfox workers in custom mode (default: 5)
  --delay               Dalfox delay in ms (default: 500)
  --timeout             Dalfox timeout in seconds (default: 30)
```

---

## 📂 Output Files

| File | Description |
|---|---|
| `subdomains.txt` | All discovered subdomains |
| `activesubdomains.txt` | Live/active subdomains only |
| `parameters.txt` | All discovered parameters |
| `singleparam.txt` | Filtered single-parameter URLs |
| `withoutfuzz.txt` | Deduplicated URLs ready for Dalfox |
| `scan` | Full Dalfox output |
| `vulnerableurl.txt` | Extracted vulnerable URLs |
| `xss_hunter_errors_*.log` | CLI error log |
| `web-run.log` | Web dashboard scan log |
| `job_state.json` | Web scan state |

Web dashboard scans are saved inside:

```text
runs/<timestamp>_<domain>_<job-id>/
```

---

## 🧹 Cleanup Before New CLI Scan

For a clean CLI run on a new target:

```bash
rm -rf results/ parameters.txt singleparam.txt withoutfuzz.txt subdomains.txt activesubdomains.txt scan vulnerableurl.txt scanned_urls.txt pending_urls.txt
```

Web mode stores each scan in its own `runs/` folder, so manual cleanup is usually not needed.

---

## 📸 Sample Output

```text
[*] Finding subdomains for: target.com
[+] 124 subdomains found! -> subdomains.txt

[*] Checking active subdomains (20 threads)...
[+] 34 active subdomains found! -> activesubdomains.txt

[*] Finding parameters using ParamSpider...
[+] 1842 parameters found (merged)! -> parameters.txt

[*] Starting Dalfox scan...
[Dalfox] running | scanned 48/312 | vulnerabilities 2

[POC][R][GET][inHTML-URL] https://target.com/page.php?id=...
[W] Reflected Payload in HTML

[+] 2 VULNERABLE URLs found! -> vulnerableurl.txt
```

---

## 🧩 Project Structure

```text
XSS-HUNTER/
├── README.md
├── LICENSE
├── install.sh
├── xsshunter
├── xsshunter.py
├── WEB_README.md
├── .gitignore
└── web/
    ├── index.html
    ├── styles.css
    └── app.js
```

---

## 🧯 Troubleshooting

### `xsshunter: command not found`

Reinstall the global launcher:

```bash
sudo ./install.sh --link-only
```

### Web server already running

```bash
pkill -f "xsshunter.py --web-server"
xsshunter --web
```

### `subfinder is not installed`

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### `dalfox is not installed`

```bash
go install -v github.com/hahwul/dalfox/v2@latest
```

### `paramspider is not installed`

```bash
pipx install git+https://github.com/devanshbatham/ParamSpider.git
```

---

## 📄 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 EnCrYpTeD05

---

## 👤 Author

**EnCrYpTeD05**

- GitHub: [@EnCrYpTeD05](https://github.com/EnCrYpTeD05)
- Website: [encrypted05.github.io](https://encrypted05.github.io)

*"Hack Smart. Hunt Hard."* 🎯

---

⭐ **If XSS Hunter helped your bug bounty workflow, drop a star on the repo!**
