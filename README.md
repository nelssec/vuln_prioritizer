# Vulnerability Prioritizer

## Overview

This tool performs risk-based vulnerability prioritization using EPSS scoring and asset criticality. It processes vulnerability scan data and generates prioritized reports with an interactive dashboard for analysis.

## What It Does

The prioritizer analyzes vulnerabilities across your infrastructure and assigns risk scores based on multiple factors:

- CVSS base scores from vulnerability data
- EPSS probability scores from FIRST.org
- CISA Known Exploited Vulnerabilities catalog
- Asset criticality levels
- Network exposure levels

Each vulnerability receives a weighted risk score that determines remediation priority. Assets are evaluated based on their average vulnerability risk.

## Requirements

Python 3.8 or higher

Required packages:
- requests
- pandas
- openpyxl

Install dependencies:
pip install requests pandas openpyxl

## Input Format

The tool accepts vulnerability scan data in CSV format with the following required columns:

- DNS: Asset hostname or identifier
- IP: Asset IP address
- CVE ID: CVE identifier
- CVSS Base: CVSS base score
- Severity: Vulnerability severity level

Optional columns for enhanced analysis:
- Title: Vulnerability title
- First Detected: Initial detection timestamp
- Last Detected: Most recent detection timestamp

## Configuration

Edit the prioritizer script to set:

Asset criticality levels:
- HIGH: Mission critical systems
- MEDIUM: Important but not critical
- LOW: Non-essential systems

Exposure levels:
- EXTERNAL: Internet-facing assets
- INTERNAL: Internal network assets
- ISOLATED: Air-gapped or restricted access

Risk score weights:
- CVSS weight: Default 0.40
- EPSS weight: Default 0.35
- CISA KEV weight: Default 0.15
- Criticality weight: Default 0.10

## Usage

Run the prioritizer:
python run_prioritizer_v3.py

The script will:
1. Load vulnerability data from CSV
2. Fetch EPSS scores from FIRST.org API
3. Check against CISA KEV catalog
4. Calculate risk scores for each vulnerability
5. Generate prioritized output files

## Output Files

The tool generates three output files:

prioritized.json: Complete vulnerability data with risk scores and metadata. Used as input for the dashboard.

prioritized.csv: Spreadsheet format for analysis and reporting. Includes all vulnerability details with calculated risk scores.

dashboard HTML: Interactive web interface for vulnerability analysis. No server required, runs entirely in browser.

## Dashboard Features

The dashboard provides:

Asset view showing risk scores and vulnerability counts per host
CVE view with detailed vulnerability information sorted by priority
Search and filter capabilities
Sortable columns
Export to CSV functionality
Detailed asset drill-down showing all associated vulnerabilities

To use the dashboard:
1. Open the HTML file in a web browser
2. Upload the generated JSON file
3. Analyze and interact with the data

## EPSS Cache

The tool maintains a local SQLite database to cache EPSS scores. This reduces API calls and improves performance on subsequent runs. The cache is automatically updated when new CVEs are encountered.

## Risk Score Calculation

Risk scores are calculated using a weighted formula:

Risk Score = (CVSS Weight × CVSS Score) + (EPSS Weight × EPSS Score) + (CISA KEV Bonus) + (Criticality Bonus)

All scores are normalized to a 0-100 scale.

Risk levels are assigned based on final scores:
- CRITICAL: 80-100
- HIGH: 60-79
- MEDIUM: 40-59
- LOW: 20-39
- MINIMAL: 0-19

## API Dependencies

FIRST.org EPSS API: Provides exploitation probability scores
CISA KEV API: Provides known exploited vulnerabilities list

Both APIs are accessed over HTTPS. No authentication required. The tool implements retry logic and rate limiting to handle API failures gracefully.

## GitHub Pages Deployment

The dashboard can be hosted on GitHub Pages for team access:

1. Create a docs folder in your repository
2. Place the index.html file in the docs folder
3. Enable GitHub Pages in repository settings
4. Select the docs folder as the source
5. Access the dashboard at username.github.io/repository-name

No server-side processing is required. All data analysis happens in the browser. Vulnerability data is never transmitted to external servers.

## Performance Considerations

Processing time scales with vulnerability count and asset count. Typical performance:

- 1000 vulnerabilities: 1-2 minutes
- 10000 vulnerabilities: 5-10 minutes
- 50000 vulnerabilities: 20-30 minutes

Most processing time is spent on EPSS API calls. Cached CVEs process instantly.

## Output Customization

Modify the script to adjust:
- Risk score thresholds
- Weight distributions
- Asset criticality mappings
- Exposure level definitions
- Output format and columns

## Limitations

The tool assumes:
- One vulnerability scan input file
- Standard CVE identifiers
- CVSS v3 scoring
- Network connectivity for API access

Assets without CVE identifiers cannot be risk-scored. Manual vulnerabilities require CVE mapping before processing.

## Data Privacy

All processing occurs locally. No vulnerability data is transmitted to external services except:
- CVE IDs sent to EPSS API for scoring
- CVE IDs sent to CISA API for KEV checking

Asset names, IP addresses, and other identifying information remain local.
