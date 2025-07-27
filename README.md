# VulnSentinel
VulnSentinel is a smart vulnerability assessment tool that scans targets using Nmap, maps detected services to known CVEs, calculates risk levels, and generates detailed reports. Ideal for students, ethical hackers, and IT pros to identify and understand security exposures efficiently.


VulnSentinel An advanced, Python-based network vulnerability scanner that integrates Nmap, NSE scripts, exploit intelligence, and persistent caching to deliver comprehensive and actionable security reports.

This tool is designed for security professionals and network administrators to perform in-depth vulnerability assessments, prioritize remediation efforts based on real-world exploitability, and visualize results through interactive reports.


Key Features

Deep Nmap Integration: Leverages Nmap for robust service detection, version fingerprinting, and OS detection.
NSE Script Engine: Directly runs powerful Nmap Scripting Engine (NSE) scripts like vulners, vuln, and vulscan to find vulnerabilities.

💥 Exploit Intelligence: Checks for publicly available exploits (including Metasploit modules) for discovered CVEs to assess real-world risk.

Advanced Risk Scoring: Calculates a weighted risk score based on CVSS, service criticality, and exploit availability.

🗄️ Persistent Caching: Uses an SQLite database to cache CVE and exploit data, speeding up subsequent scans and reducing API calls.

📊 Rich Reporting: Generates reports in multiple formats (html, json, txt), including an interactive HTML report with charts and detailed remediation advice.

📜 Scan History: Keeps a record of past scans for trend analysis and comparison.

💅 Rich CLI: Provides a modern, user-friendly command-line interface with progress bars and color-coded summaries.
## Features

- Scans target IP or domain using `nmap` with version detection
- Parses Nmap output and extracts service/version details
- Queries CIRCL/NVD for known CVEs related to identified services
- Calculates risk severity using a custom risk engine
- Generates reports in HTML, JSON, and plaintext
- CLI support with arguments for target, port range, and format
- Modular and extensible architecture



## Installation

> Nmap must be installed and accessible from your system’s PATH.

```bash
# Clone the repo
git clone https://github.com/abdulfaisal001/VulnSentinel.git
cd VulnSentinel

# Install Python dependencies
pip install -r requirements.txt
```

| Argument           | Alias | Description                                                 | Default      |
| ------------------ | ----- | ----------------------------------------------------------- | ------------ |
| `target`           | —     | Target IP address, hostname, or CIDR range                  | *(Required)* |
| `--ports`          | `-p`  | Port range to scan (e.g., `1-1000`, `80,443`)               | `1-1000`     |
| `--output`         | `-o`  | Path to save the report file                                | *Automatic*  |
| `--format`         | `-f`  | Report format: `html`, `json`, or `txt`                     | `html`       |
| `--scripts`        | —     | NSE vulnerability scripts to use (`vulners`, `vuln`, etc.)  | `vulners`    |
| `--os-detection`   | —     | Enable Nmap's OS detection (`-O` flag)                      | `False`      |
| `--skip-intrusive` | —     | Avoid potentially disruptive NSE scripts for safer scanning | `False`      |
| `--show-history`   | —     | Display previous scan history for the specified target      | `False`      |
| `--cleanup-cache`  | —     | Clear old cache entries before starting a new scan          | `False`      |
| `--verbose`        | `-v`  | Enable detailed logging output for debugging                | `False`      |




| Use Case                            | Command                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------- |
| **Basic Scan of a Single Host**     | `python main.py 192.168.1.101`                                                  |
| **Scan a Subnet with OS Detection** | `sudo python main.py 192.168.1.0/24 --os-detection --output subnet_report.html` |
| **Advanced Scan with All Scripts**  | `python main.py target.example.com -p 1-65535 --scripts all --skip-intrusive`   |
| **Generate a JSON Report**          | `python main.py 10.0.0.5 --format json -o api_report.json`                      |
| **View Scan History for a Target**  | `python main.py 10.0.0.5 --show-history`                                        |


requests
xmltodict
jinja2
bash pip install requests xmltodict jinja2


Project Structure :


.
├── main.py
├── templates/
│   └── report_template.html
├── reports/
│   └── vuln_report_<timestamp>.html
├── requirements.txt
└── README.md
