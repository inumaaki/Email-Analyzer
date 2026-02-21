# Email Analyzer (EA) - Threat Hunting & Analysis

With Email Analyzer, security analysts and SOC teams can quickly investigate suspicious `.eml` and `.msg` files locally. It parses headers, extracts Indicators of Compromise (IOCs), hashes files, and provides a clear, single-pane-of-glass terminal dashboard layout for rapid triaging.

## Features

- **Offline-First Analysis**: Core parsing and extraction are done locally to maintain OPSEC.
- **Compact Dashboard Layout**: All critical information is displayed without scrolling, fitting neatly into your terminal window.
- **Spoof Checking**: Automatically compares the `From` and `Reply-To` headers to detect spoofing attempts.
- **Cryptographic Hashing**: Calculate MD5, SHA1, and SHA256 for the overall email file and its content.
- **IOC Extraction & Defanging**: Pulls URLs, IP addresses, and emails out from the email body and natively defangs them (e.g., `hxxp[://]example[.]com`) for safe handling.
- **One-Click OSINT Pivot Links**: Generates full plain-text investigation URLs for VirusTotal and UrlScan explicitly formatted for copy-pasting in standard Linux/Kali terminals.
- **Threat Intel Enrichment**: Seamlessly integrates with VirusTotal and AbuseIPDB when API keys are present.
- **Attachment Handling**: Identifies suspicious extensions and safely dumps requested attachments to a local sandboxed directory (`./analysis/output/`).
- **Deep Static Analysis (WIP)**: Support for optional deep analysis using `oletools` and `pdfid` for malicious documents is scaffolded via the `--deep` flag for future implementation.

## Installation

1. Clone or download the repository.
2. Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

3. Rename the `.env.example` to `.env` (or create a new `.env` file) to add your API keys:

```ini
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here
```
*(If you do not specify API keys, the tool will still provide the full terminal dashboard using offline heuristics.)*

## Usage

### Basic Analysis

To perform a fast, offline extraction of a suspicious email file and view the dashboard:

```bash
python3 main.py -f suspicious.eml
```

### Enable Threat Intel Enrichment

If you have populated your `.env` file with API keys, the tool will **automatically** query the relevant endpoints:

```bash
python3 main.py -f suspicious.eml
```
> **Note**: As long as `VT_API_KEY` or `ABUSEIPDB_API_KEY` exists, the `--enrich` switch is flipped on automatically and live scores will be injected directly into the "Live Threat Intel" panel.

### Extract Attachments to Sandbox

To dump embedded attachments to your local disk output folder (default is `./analysis/output/`):

```bash
python3 main.py -f suspicious.eml --extract-attachments
```

### Deep Analysis of Attachments

To run extended YARA rules, oletools, and pdfid parsing against extracted attachments:

```bash
python3 main.py -f suspicious.eml --deep
```

### Export to JSON (Silent Mode)

If you are automating triage pipelines and just want raw data exported to JSON without terminal output:

```bash
python3 main.py -f suspicious.eml --export output.json --silent
```

## Dashboard Overview

Here's an overview of the blocks you'll see in the terminal Output:

1. **Basic Headers**: Date, sender, recipient, and subject information.
2. **File Hashes**: MD5 and SHA-2 for the underlying `.eml` file and its aggregated body text.
3. **Auth & Routing**: Results from SPF, DKIM, and DMARC validations, along with domain spoof checks.
4. **Risk Assessment**: Heuristic scoring (0-100) assigning a risk level based on aggregated indicators.
5. **Content Analysis**: Identifies phishing keywords or suspicious HTML constructs (like hidden forms).
6. **Extracted IOCs**: Defanged URLs, IPs, and Email addresses parsed from the body.
7. **Attachments**: General attachment information (sizing, malicious extension warnings).
8. **Live Threat Intel**: Raw vendor breakdown dynamically queried from VirusTotal and AbuseIPDB.
9. **One-Click Investigation Links**: Generated copy-pasteable dashboard links to instantly jump out to VT/UrlScan GUI pages.
