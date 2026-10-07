# NETFORGE

## Network Security Testing & Assessment Platform

NETFORGE is a Kali Linux-based network security testing and assessment platform designed to combine network discovery, service analysis, DNS inspection, traceroute analysis, traffic monitoring, risk assessment, scan history, analytics, and HTML reporting into a single web-based interface.

The project uses a Python Flask backend with native security/networking tools and a responsive HTML, CSS, and JavaScript dashboard.

---

## Features

### Network Scanning

* Nmap-based service discovery
* Service and version detection
* Configurable target input
* Local laboratory scanning
* Authorized external assessment mode

### Security Analysis

* Detected service classification
* Severity identification
* Risk scoring
* Security-level calculation
* Security recommendations

### DNS Analysis

* Hostname resolution
* IPv4 detection
* IPv6 detection
* DNS error detection

### Network Path Analysis

* Traceroute execution
* Hop/path visibility
* Network troubleshooting information

### Traffic Analysis

* TShark interface discovery
* Live packet capture
* Source and destination identification
* Protocol detection
* TCP/UDP port information
* Packet-count analysis

### Risk Engine

NETFORGE combines multiple assessment signals into a normalized risk score.

|  Score | Security Level |
| -----: | -------------- |
|   0–24 | LOW            |
|  25–49 | MEDIUM         |
|  50–74 | HIGH           |
| 75–100 | CRITICAL       |

### Scan History

NETFORGE stores scan summaries using SQLite.

Stored information includes:

* Target
* Scan date
* Risk score
* Security level
* Severity counts
* DNS status
* Traffic status
* Packet count

### Analytics

The dashboard provides:

* Risk-score trends
* Severity distribution
* Scan statistics
* Historical assessment information

### Reporting

NETFORGE generates professional HTML security assessment reports containing:

* Executive summary
* Risk score
* Security level
* Findings
* DNS information
* Traffic information
* Traceroute information
* Recommendations

---

# Architecture

```text
                         NETFORGE
                            |
                            v
                  +-------------------+
                  |   Web Dashboard   |
                  | HTML/CSS/JavaScript|
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  |   Flask Backend   |
                  +---------+---------+
                            |
        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
   +---------+         +---------+         +---------+
   |  Nmap   |         |  DNS    |         |TShark   |
   | Scanner |         |Analyzer |         |Traffic  |
   +----+----+         +----+----+         +----+----+
        |                   |                   |
        +-------------------+-------------------+
                            |
                            v
                  +-------------------+
                  |   Risk Engine     |
                  +---------+---------+
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          +-------------+       +-------------+
          |   SQLite    |       |   Report    |
          | Scan History|       |  Generator  |
          +-------------+       +-------------+
```

---

# Project Structure

```text
NETFORGE/
│
├── backend/
│   ├── app.py
│   ├── analyzer.py
│   ├── dns.py
│   ├── network.py
│   ├── reporter.py
│   ├── risk_engine.py
│   ├── scanner.py
│   ├── target_policy.py
│   └── traffic.py
│
├── database/
│   ├── __init__.py
│   ├── database.py
│   └── netforge.db
│
├── frontend/
│   ├── index.html
│   └── dashboard.html
│
├── tools/
│   ├── __init__.py
│   ├── nmap_runner.py
│   ├── tshark_runner.py
│   └── traceroute_runner.py
│
├── reports/
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

# Technology Stack

| Component             | Technology              |
| --------------------- | ----------------------- |
| Operating System      | Kali Linux              |
| Backend               | Python                  |
| Web Framework         | Flask                   |
| Frontend              | HTML5, CSS3, JavaScript |
| Database              | SQLite                  |
| Network Scanner       | Nmap                    |
| Packet Analyzer       | TShark                  |
| Network Path Analysis | Traceroute              |
| DNS Analysis          | Python Socket           |
| Reporting             | HTML                    |
| Charts                | Chart.js                |
| Version Control       | Git                     |

---

# Requirements

NETFORGE is designed for Kali Linux.

Required software:

* Python 3
* Flask
* Nmap
* TShark
* Traceroute
* Git

Check the installed tools:

```bash
python3 --version
nmap --version
tshark --version
traceroute --version
git --version
```

---

# Installation

Clone the project:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd NETFORGE
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Verify Flask:

```bash
python -c "import flask; print(flask.__version__)"
```

---

# Running NETFORGE

From the project directory:

```bash
cd ~/NETFORGE
source .venv/bin/activate
python backend/app.py
```

The application runs on:

```text
http://127.0.0.1:5000
```

Open the dashboard in your browser:

```text
http://127.0.0.1:5000/dashboard
```

---

# Local Laboratory Mode

NETFORGE provides a Local Lab mode for testing systems within an authorized laboratory environment.

Example:

```text
127.0.0.1
```

Private laboratory addresses may also be used where appropriate.

Example:

```text
192.168.1.10
```

The target authorization policy prevents public targets from being accidentally assessed while operating in Local Lab mode.

---

# Authorized External Mode

NETFORGE also provides an Authorized External mode for legitimate security assessments.

External targets should only be tested when the tester has explicit authorization from the owner or organization responsible for the system.

The dashboard includes an additional authorization confirmation before an external assessment can be started.

> Never use NETFORGE to scan systems without permission.

---

# Basic Workflow

```text
1. Start NETFORGE
        |
        v
2. Open Dashboard
        |
        v
3. Select Scan Mode
        |
        v
4. Enter Authorized Target
        |
        v
5. Run Nmap Scan
        |
        v
6. Analyze Services
        |
        v
7. Perform DNS Analysis
        |
        v
8. Analyze Network Path
        |
        v
9. Capture Traffic
        |
        v
10. Calculate Risk
        |
        v
11. Save Scan History
        |
        v
12. Generate HTML Report
```

---

# API Endpoints

## Backend Status

```http
GET /
```

Returns the current backend status.

---

## Dashboard

```http
GET /dashboard
```

Loads the NETFORGE web dashboard.

---

## Target Policy

```http
GET /api/policy
```

Returns target authorization policy information.

---

## Network Scan

```http
POST /api/scan
```

Example request:

```json
{
    "target": "127.0.0.1",
    "mode": "local"
}
```

---

## DNS Analysis

```http
POST /api/dns
```

Example:

```json
{
    "target": "localhost",
    "mode": "local"
}
```

---

## Traceroute

```http
POST /api/traceroute
```

Example:

```json
{
    "target": "127.0.0.1",
    "mode": "local"
}
```

---

## Traffic Interfaces

```http
GET /api/traffic/interfaces
```

Returns available TShark interfaces.

---

## Traffic Capture

```http
POST /api/traffic
```

Captures network traffic through the selected interface.

---

## Risk Assessment

```http
POST /api/risk
```

Calculates the combined security risk.

---

## Scan History

```http
GET /api/history
```

Returns previous scan summaries.

---

## Individual Scan

```http
GET /api/history/<scan_id>
```

Returns a specific historical scan.

---

## Analytics

```http
GET /api/analytics
```

Returns dashboard analytics.

---

## Report Generation

```http
POST /api/report
```

Generates an HTML security assessment report.

---

# Security Design

NETFORGE includes a target authorization layer before network operations are performed.

The authorization policy distinguishes between:

```text
LOCAL LAB
    |
    +-- localhost
    +-- loopback
    +-- private laboratory addresses
    +-- private laboratory hostnames


AUTHORIZED EXTERNAL
    |
    +-- Explicitly authorized external assessment
```

This design helps reduce accidental scanning of public systems.

---

# Risk Assessment Model

NETFORGE assigns weighted values to detected findings.

Example:

```text
HIGH       → 25 points
MEDIUM     → 15 points
LOW        → 5 points
INFO       → 0 points
```

Additional assessment signals can contribute to the overall score.

The final score is normalized between:

```text
0 - 100
```

The system then maps the score to a security level.

```text
0–24     LOW
25–49    MEDIUM
50–74    HIGH
75–100   CRITICAL
```

---

# Example Finding

An exposed SSH service may produce a finding similar to:

```json
{
    "port": "22/tcp",
    "service": "ssh",
    "severity": "LOW",
    "risk": 20,
    "recommendation": "Keep SSH updated, disable unnecessary access, and use strong authentication."
}
```

The purpose of this analysis is to help identify services that should be reviewed rather than automatically declaring a service vulnerable.

---

# Database

NETFORGE uses SQLite for lightweight local scan-history storage.

Database:

```text
database/netforge.db
```

The database is intentionally excluded from Git through `.gitignore`.

This prevents local scan history from accidentally being committed to a public repository.

---

# Reports

Generated reports are stored locally in:

```text
reports/
```

Example:

```text
NETFORGE_Report_20261005_153000.html
```

Generated reports are excluded from Git by default.

---

# Screenshots

Add project screenshots here after final testing.

Recommended screenshots:

```text
docs/screenshots/
├── dashboard.png
├── scan-results.png
├── risk-analysis.png
├── traffic-analysis.png
└── report.png
```

Example Markdown:

```markdown
![NETFORGE Dashboard](docs/screenshots/dashboard.png)

![Risk Analysis](docs/screenshots/risk-analysis.png)
```

---

# Testing

Basic backend test:

```bash
curl http://127.0.0.1:5000/
```

Expected response should indicate that the NETFORGE backend is online.

Test Nmap:

```bash
python tools/nmap_runner.py
```

Test DNS:

```bash
python backend/dns.py
```

Test traceroute:

```bash
python backend/network.py
```

Test traffic analysis:

```bash
sudo python backend/traffic.py
```

Test target policy:

```bash
python backend/target_policy.py
```

---

# Project Goals

NETFORGE was developed to demonstrate practical understanding of:

* Network security
* Network reconnaissance
* Service identification
* Security assessment
* Packet analysis
* DNS analysis
* Network troubleshooting
* Risk scoring
* Security reporting
* Python development
* Flask API development
* SQLite database management
* Web dashboard development
* Linux security tooling

---

# Future Enhancements

Potential future improvements include:

* CVE intelligence integration
* Improved service fingerprinting
* Advanced packet statistics
* Port trend analysis
* PDF report generation
* Authentication and user accounts
* Role-based access control
* Configurable scan profiles
* Scheduled authorized assessments
* Export to CSV/JSON
* Additional security checks
* Improved historical scan comparison
* Offline dashboard assets
* More advanced risk scoring

---

# Responsible Use

NETFORGE is intended for:

* Personal security laboratories
* CTF environments
* Authorized penetration-testing environments
* Educational cybersecurity training
* Systems owned by the tester
* Systems for which explicit testing permission has been obtained

Do not use NETFORGE to scan or assess systems without authorization.

The developer is not responsible for misuse of this software.

---

# Author

**Sagar H.**

Cybersecurity / Network Security Project

---

# License

This project is intended as an educational and portfolio cybersecurity project.

Add an appropriate open-source license before publishing if you want others to redistribute or modify the project.
