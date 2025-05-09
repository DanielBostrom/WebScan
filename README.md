# 🌐 WebScan 🌐 

**WebScan** 
is a fast and feature-rich web directory scanner designed for application security professionals, bug bounty hunters, and CTF participants. It performs intelligent path discovery, crawling, JavaScript analysis, and vulnerability testing—all in one tool.

## 🚀 Features

- 🔍 **Directory scanning** with a custom wordlist
- 🧪 **Multiple HTTP methods**: GET, POST, HEAD
- 🕸️ **HTML crawling** to discover new paths
- 📜 **JavaScript route analysis** to extract hidden endpoints
- 🔐 **Built-in vulnerability detection**:
  - SQL Injection
  - Cross-site Scripting (XSS)
  - Local File Inclusion (LFI) / Path Traversal
  - Open Redirects
  - Missing security headers
- 🧠 **Interactive mode** for manual review and actions
- 📤 **Export results** in TXT, CSV, HTML, or JSON
- 🎨 **Optional colorized terminal output**

---

## 📦 Installation

Install required dependencies:

```bash
pip install -r requirements.txt
```

## ⚙️ Usage
python3 webscan.py -u http://example.com -w wordlist.txt [options]

## OPTIONS 
Option	Description
-u, --url	Base URL to scan (required)
-w, --wordlist	Path to the wordlist file (required)
-e, --extensions Comma-separated extensions (e.g. php,html,js)
-t, --threads	Number of threads (default: 10)
--timeout	Timeout in seconds (default: 5)
--methods	HTTP methods to test (e.g. GET,POST)
--crawl	Enable crawling to discover additional paths
--js-analysis	Extract routes from JavaScript files
--full	Enable all discovery methods (--crawl + --js-analysis)
-i, --interactive	Start interactive mode after scanning
-o, --output	Save results to output file
--no-color	Disable colored output
--version	Show version and exit

🧪 Example Usage
python3 webscan.py -u http://localhost:8000 -w wordlist.txt -e php,html --crawl --interactive

🧠 Interactive Mode
When using --interactive, you can:

List discovered results

Open URLs in your browser

View response content and headers

Search URLs by keyword

Run vulnerability tests

Extract links, scripts, forms, etc.

Export results (txt, csv, html, json)

🔐 Vulnerability Scanning
Built-in tests for:

🧨 SQL Injection – detects SQL error messages and response anomalies

🛡️ XSS – tests for reflected payloads in response content

🗂️ LFI/Path Traversal – tests for known traversal patterns

🔁 Open Redirect – checks for unsafe redirection endpoints

🧾 Security Headers – detects missing headers like CSP, X-Frame-Options, HSTS

📤 Exporting Results
Export formats supported via --output or from the interactive menu:

.txt – Plain text

.csv – Spreadsheet format

.html – Clickable styled report

.json – Structured data for scripting

🧰 Recommended Wordlists
For best results, use:

SecLists

Recommended: Discovery/Web-Content/common.txt

You can also combine this with --js-analysis to detect routes used in front-end JavaScript.

⚠️ Legal Disclaimer ⚠️
WebScan is intended for authorized testing and educational purposes only.
Do not scan systems without explicit permission.

