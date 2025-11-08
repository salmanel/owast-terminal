# 🛡️ TSA Web Tester — OWASP Vulnerability Scanner (Terminal Edition)

**Version:** v1.0.1  
**Author:** TSA Security Labs — by SELY  
**License:** MIT  
**Language:** Python 3.10+  

A modular, terminal-based web vulnerability scanner inspired by OWASP Testing Guide v4.2.  
It detects common security flaws (Headers, XSS, SQL Injection) and exports professional reports in JSON, HTML, Markdown, CSV, and PDF formats.

---

## 🚀 Features

| Module | Description |
|:--|:--|
| **🕷️ Crawler** | Multi-page recursive crawler with configurable depth, host restrictions, and polite delay. |
| **🧩 Header Analyzer** | Checks missing security headers (CSP, X-Frame-Options, etc.) across all pages. |
| **💉 Injector** | Tests query params and form inputs for XSS & SQLi payloads (reflective and error-based). |
| **🧠 Configurable Scanner** | Supports both **Quick Scan** (default config) and **Advanced Scan** (custom rules, payloads, JS rendering). |
| **🧱 Terminal UI** | Interactive 8-option CLI with Star-Wars-style banner and color-coded severity results. |
| **📊 Report System** | Generates JSON + HTML + Markdown + CSV + PDF reports, sorted by severity (HIGH → MEDIUM → INFO). |
| **⚙️ Extensible Architecture** | Easily add new OWASP modules (e.g., CSRF, SSRF, RCE, etc.) via `core/modules/`. |
| **💾 Resume-ready Reports** | Export or share findings with collaborators or CI/CD tools. |

---

## 🧱 Project Structure

```
owasp-tester-terminal/
├── cli.py
├── tools/
│   └── terminal_ui.py
├── config.yaml
├── core/
│   ├── wvscanner_core.py
│   ├── crawler.py
│   ├── injector.py
│   ├── utils.py
│   └── reporters/
│       ├── json_reporter.py
│       ├── html_reporter.py
│       ├── csv_reporter.py
│       └── md_reporter.py
├── reports/
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/<your-org>/owasp-tester-terminal.git
cd owasp-tester-terminal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Required libraries**
```
requests
urllib3
colorama
tabulate
pyyaml
reportlab
```

---

## 🖥️ Usage

### 1️⃣ Run Quick Scan (CLI)
```bash
python cli.py --url http://testphp.vulnweb.com/ --config config.yaml --out reports --debug --details
```

### 2️⃣ Run the Interactive Terminal UI
```bash
python tools/terminal_ui.py
```

**Menu Options:**
```
1) Quick scan
2) Advanced scan (override config, custom payloads)
3) List latest reports
4) View a report in terminal (JSON)
5) Open HTML / Export (MD/CSV/PDF/Bundle)
6) Show raw JSON of a report
7) Delete a report
8) Open latest HTML report
0) Exit
```

---

## 📜 Report Formats

| Format | Description | Location |
|:--|:--|:--|
| `.json` | Machine-readable raw results | `/reports/*.json` |
| `.html` | Interactive visual report | `/reports/*.html` |
| `.md` | Markdown summary | `/reports/*.md` |
| `.csv` | Spreadsheet export | `/reports/*.csv` |
| `.pdf` | Printable version | `/reports/*.pdf` |

---

## 🧩 Current OWASP Coverage

| Category | Sub-Checks |
|:--|:--|
| **A05:2021 – Security Misconfiguration** | Missing HTTP security headers |
| **A03:2021 – Injection** | SQL Injection (error-based and reflected) |
| **A07:2021 – Identification & Auth** | To be added |
| **A03:2021 – XSS** | Reflected XSS detection |
| **A08:2021 – Software Data Integrity** | Planned |
| **A09:2021 – Security Logging** | Planned |

---

## 🧠 Developer Notes

- Add new OWASP modules in `core/modules/`.
- The scanning engine auto-detects modules implementing `run_<module>_checks()`.
- To expand attacks, update payload files in `payloads/` or link external repositories (e.g. PayloadBox).

---

## 🧰 Roadmap

| Phase | Feature | Status |
|:--|:--|:--|
| v1.0.1 | CLI + Terminal UI | ✅ Completed |
| v1.1.0 | CSRF / SSRF / Command Injection checks | 🔄 In progress |
| v1.2.0 | Access Control & Directory Traversal | ⏳ Planned |
| v1.3.0 | AI-powered payload generator | 🔬 Research stage |

---

## 📜 License

MIT License — use freely with attribution.
