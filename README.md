# 🔍 AresNet

**Advanced Network & Vulnerability Scanner for Security Analysts.**

---

## 🚀 About AresNet

AresNet is a powerful Python-based advanced network and vulnerability scanner that supports:

- High-speed TCP/UDP port scanning
- Active vulnerability detection
- Nmap NSE script integration
- CVE metadata enrichment
- Live reporting to HTML, JSON, and CSV

Perfect for live recon, red teaming, and real-world vulnerability discovery.

---

## 🔧 Features

✅ High-speed TCP & UDP port scanning  
✅ Banner grabbing and active fingerprinting  
✅ CVE/CWE/CVSS enrichment via Vulners API  
✅ OS detection (TTL-based)  
✅ Full Nmap NSE script support (including custom scripts)  
✅ Advanced scan modes for TCP, UDP, or both  
✅ Real-time CLI output and structured reporting (JSON/CSV/HTML)  
✅ HTML output with color-coded severity

---

## 📸 Demo



```bash
$ python3 aresnet.py -t <Target> -p 80 --ad-scan --script=all -o <File name> --json --csv --html
```

---


## 🛠️ Installation

1. **Clone the repo**:

```bash
git clone https://github.com/Pushprajsinh12/aresnet.git
cd aresnet
```

2. **Create a virtual environment**:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install requirements** 

```bash
pip install tqdm
```

---

## 💻 Supported Platforms & Requirements AresNet works on:

✅ Kali Linux

✅ macOS

✅ Linux

✅ Windows	

📦 Prerequisites
Requirement Description
Python 3.8+ Required to run the tool
Nmap    Required for Nmap-based scans and NSE scripts
tqdm    For visual progress bar
nmap CLI    Must be installed and accessible in your system

ℹ️ Note: On macOS, use brew install nmap. On Debian-based Linux: sudo apt install nmap.

✅ Add pip requirements file Create a requirements.txt file:

```bash 
pip install -r requirements.txt 
```

✅ Mention VENV for Windows Update the virtual environment part like this:

### Linux/macOS

```bash
python3 -m venv venv source venv/bin/activate
```

### Windows (PowerShell)

```bash
python -m venv venv .\venv\Scripts\activate
```

## ⚙️ Usage

#### 🔎 Basic Scan (TCP/UDP)

```bash
python3 aresnet.py -t <target>
```

#### 📌 Custom Port Range

```bash
python3 aresnet.py -t <target> -p 0-65535
```

#### ⚡ Run Advanced Scan (TCP + UDP NSE scripts)

```bash
python3 aresnet.py -t <target> --ad-scan --script=all
```

#### 🔓 TCP Advanced Scan Only
```bash
python3 aresnet.py -t <target> --ad-scan --script=all -at
```

#### 🔐 UDP Advanced Scan Only
```bash
python3 aresnet.py -t <target> --ad-scan --script=all -au
```

#### 🧪 Run Specific Script
```bash
python3 aresnet.py -t <target> --script=ftp-anon
```

#### 📂 Run Multiple or Custom Scripts
```bash
python3 aresnet.py -t <target> --script=default,vuln
python3 aresnet.py -t <target> --script=/path/to/custom.nse
```

#### 🤖 Skip Host Discovery (for offline hosts)

```bash
python3 aresnet.py -t <target> --ad-scan --skip-pn
```

#### 🧪 Run All Available Scripts

```bash
python3 aresnet.py -t <target> --script=all
```

#### 📤 Export Options

```bash
python3 aresnet.py -t <target> --output report -o report --json --csv --html
Supports .json, .csv, .html
```

## 📊 Output Sections

TCP Results

UDP Results

TTL-based OS Detection

Vulnerabilities with severity, CVE, CVSS score, and references

## ✍️ Flag Reference Table

| Flag                        | Description                                                |
| --------------------------- | ---------------------------------------------------------- |
| `-h, --help`                | Show help message and exit                                 |
| `-t, --target TARGET`       | Target IP address or hostname                              |
| `-p, --ports PORTS`         | Port(s) to scan (e.g. 80, 1-100)                           |
| `-sU, --udp`                | Enable UDP port scanning                                   |
| `-sV, --banner`             | Grab service banners and analyze for vulnerabilities       |
| `--threads THREADS`         | Number of threads (default: 100)                           |
| `--discover`                | Enable host discovery                                      |
| `--show-all`                | Show all ports, including closed ones                      |
| `--output OUTPUT`           | Save output to a file                                      |
| `-O, --os-detect`           | Enable OS detection                                        |
| `-T, --timing TIMING`       | Timing profile (T0-T5, default: T3)                        |
| `--json`                    | Export scan results in JSON format                         |
| `--csv`                     | Export scan results in CSV format                          |
| `--html`                    | Export scan results in HTML format                         |
| `--html-file HTML_FILE`     | Custom HTML report filename (default: `scan_results.html`) |
| `--ad-scan`                 | Use AresNet Advanced Scan (Nmap-based)                     |
| `-at`                       | Run TCP advanced scan only                                 |
| `-au`                       | Run UDP advanced scan only                                 |
| `--no-sudo`                 | Run Nmap without sudo (use `-sT` scan)                     |
| `--skip-pn`                 | Treat host as online (skip ping check)                     |
| `--script` 				          | Run Nmap NSE scripts (single, multiple, or all)            |

---

## 📁 Output Formats

* `scan_results.json` – structured JSON for further automation.
* `scan_results.csv` – tabular data for Excel or CLI tools.
* `scan_results.html` – color-coded report for easy viewing.

## 📁 Sample Commands

```bash
python3 aresnet.py -t <target ip> -p 0-65535 --udp --script=all --ad-scan --script=all --0 <File name> --json --csv --html
```

---

## 🧠 How It Works

1. Performs TCP & UDP port discovery
2. Grabs service banners and detects basic vulnerabilities
3. Runs Nmap NSE scripts (default, vuln, custom)
4. Enriches results with CVE/CWE/Severity via Vulners API
5. Exports output to terminal + optional JSON, CSV, HTML

---

## 🐞 Bug Bounty & Pentest Usage
• AresNet is designed to scan real IPs for live services and known vulnerabilities.
• Automatically detects vulnerable services
• Combines fast port scanning with active vulnerability testing
• Integrates custom scripts and full Nmap functionality
• Enriches with CVE metadata for reporting
• Just pass `--ad-scan` and you’ll get live metadata-enriched vulnerabilities — useful for bounty recon and reporting.

---

## 📜 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author
Developed by [Karan Bharda](https://github.com/scarcemrk)
