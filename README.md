# Vulnerability Prioritizer

Risk-based vulnerability prioritization using CVSS, EPSS, asset context, CISA KEV, and extensible threat intelligence.

## Architecture

```
run_prioritizer.py (CLI)
    |
vulnerability_prioritizer.py (Orchestrator)
    |
    +-- connectors/
    |   +-- base.py                   # NormalizedVulnerability, ScannerConnector, ThreatIntelProvider ABCs
    |   +-- scanners/
    |   |   +-- nessus.py             # Nessus/Tenable .nessus XML
    |   |   +-- qualys_csv.py         # Qualys CSV exports
    |   |   +-- qualys_xml.py         # Qualys XML exports
    |   |   +-- openvas.py            # OpenVAS CSV/XML
    |   |   +-- rapid7.py             # Rapid7 InsightVM/Nexpose CSV
    |   |   +-- blackduck.py          # BlackDuck SCA CSV
    |   +-- threat_intel/
    |       +-- epss.py               # FIRST.org EPSS (no auth)
    |       +-- cisa_kev.py           # CISA KEV catalog (no auth)
    |       +-- nvd.py                # NVD API v2 (no auth)
    |       +-- osv.py                # OSV.dev batch API (no auth)
    |       +-- vulners.py            # Vulners (optional API key)
    |       +-- exploitdb.py          # Local searchsploit index
    |       +-- crowdstrike.py        # CrowdStrike Falcon (stub)
    |       +-- tenable_tvm.py        # Tenable TVM (stub)
    |       +-- wiz.py                # Wiz cloud security (stub)
    |
    +-- engine/
    |   +-- correlator.py             # Merge vulns by (CVE, asset_ip)
    |   +-- scorer.py                 # Scoring profiles (cloud/onprem/oss/default)
    |
    +-- cache/
        +-- store.py                  # Generic TTL-aware FeedCache
```

## Installation

```bash
git clone https://github.com/nelssec/vuln_prioritizer.git
cd vuln_prioritizer
pip install requests
```

## Usage

```bash
python3 run_prioritizer.py --source qualys scan.csv
```

### Data Sources

| Source | Format | Flag |
|--------|--------|------|
| Nessus | .nessus XML | `--source nessus` |
| Tenable | .nessus XML | `--source tenable` |
| Qualys | CSV or XML | `--source qualys` |
| OpenVAS | CSV or XML | `--source openvas` |
| Rapid7 | CSV | `--source rapid7` |
| BlackDuck | CSV | `--source blackduck` |

### CLI Options

```
--source        Source type (nessus/tenable/qualys/openvas/rapid7/blackduck)
--profile       Scoring profile (default/cloud_workload/onprem_server/oss_library)
--output-format Output format (json/splunk/elastic)
--top-n         Number of vulnerabilities to display (default: 20)
--no-cache      Skip cache, fetch fresh EPSS/KEV data
--cache-db      Cache database path (default: epss_cache.db)
--output-prefix Custom output filename prefix
--config        Config file (default: prioritizer_config.json)
```

### Scoring Profiles

| Profile | Use Case | Weight Distribution |
|---------|----------|-------------------|
| `default` | Balanced | CVSS 30%, EPSS 25%, KEV 20%, Exploit 25% |
| `cloud_workload` | Cloud VMs/containers | CVSS 25%, EPSS 30%, KEV 20%, Exploit 25% |
| `onprem_server` | On-premises servers | CVSS 30%, EPSS 25%, KEV 20%, Exploit 25% |
| `oss_library` | SCA/open-source deps | CVSS 20%, EPSS 20%, KEV 15%, Exploit 20%, Patch 25% |

### Output Formats

- **json** (default) - Standard JSON array
- **splunk** - Splunk HEC-compatible NDJSON (one event per line)
- **elastic** - Elastic ECS-compatible bulk API format

## How It Works

1. **Parse** - Scanner connectors normalize raw scan data into `NormalizedVulnerability` objects
2. **Correlate** - Merge duplicate (CVE, asset) pairs across scanners
3. **Enrich** - Threat intel providers add EPSS, KEV, NVD, exploit data
4. **Score** - Risk scores calculated using configurable weight profiles
5. **Prioritize** - Vulnerabilities ranked with override conditions for critical combos

### Risk Levels

- **CRITICAL** (80-100) - Immediate action required
- **HIGH** (60-79) - Patch within 7 days
- **MEDIUM** (40-59) - Patch within 30 days
- **LOW** (20-39) - Patch within 90 days
- **MINIMAL** (0-19) - Schedule with routine maintenance

## Configuration

Edit `prioritizer_config.json`:

```json
{
  "connectors": {
    "scanners": {
      "nessus": "connectors.scanners.nessus.NessusConnector"
    },
    "threat_intel": [
      "connectors.threat_intel.epss.EPSSProvider",
      "connectors.threat_intel.cisa_kev.CISAKEVProvider"
    ]
  },
  "scoring_profiles": {
    "default": { "cvss": 0.30, "epss": 0.25, "kev": 0.20, "exploit": 0.25 }
  },
  "cache_ttls": {
    "epss": 7, "cisa_kev": 1, "nvd": 7
  }
}
```

### Commercial Adapter Setup

Commercial adapters are stubs that require credentials:

**CrowdStrike Falcon:**
```json
{
  "crowdstrike_client_id": "YOUR_CLIENT_ID",
  "crowdstrike_client_secret": "YOUR_CLIENT_SECRET"
}
```

**Tenable TVM:**
```json
{
  "tenable_access_key": "YOUR_ACCESS_KEY",
  "tenable_secret_key": "YOUR_SECRET_KEY"
}
```

**Wiz:**
```json
{
  "wiz_client_id": "YOUR_CLIENT_ID",
  "wiz_client_secret": "YOUR_CLIENT_SECRET"
}
```

These adapters skip gracefully when credentials are not configured.

## API Requirements

Free (no auth required):
- EPSS: https://api.first.org/data/v1/epss
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://services.nvd.nist.gov/rest/json/cves/2.0
- OSV: https://api.osv.dev/v1/querybatch

Optional API key:
- Vulners: Set `vulners_api_key` in config (works without key at lower rate limits)

Local:
- ExploitDB: Uses local `searchsploit` index if installed

## Examples

```bash
# Basic Qualys CSV scan
python3 run_prioritizer.py --source qualys vulnerabilities.csv

# Nessus scan with cloud scoring profile
python3 run_prioritizer.py --source nessus --profile cloud_workload scan.nessus

# BlackDuck SCA with OSS library profile
python3 run_prioritizer.py --source blackduck --profile oss_library components.csv

# Splunk-compatible output
python3 run_prioritizer.py --source qualys --output-format splunk scan.csv

# Top 50 with fresh data
python3 run_prioritizer.py --source qualys --top-n 50 --no-cache scan.csv
```

## Troubleshooting

**No results**: Check that your scan file contains CVE identifiers.

**API errors**: System works offline but with reduced accuracy. Check network access to api.first.org and cisa.gov.

**Memory issues**: For large scans (>10k vulnerabilities), increase Python heap size.

## License

MIT
