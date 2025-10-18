# Vulnerability Prioritizer

Risk-based vulnerability prioritization using CVSS, EPSS, asset context, and CISA KEV data.

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

- `qualys` - Qualys CSV exports
- `nessus` - Nessus .nessus files  
- `tenable` - Tenable .nessus exports

### Options

```
--source        Source type (qualys/nessus/tenable)
--top-n         Number of vulnerabilities to display (default: 20)
--no-cache      Skip cache, fetch fresh EPSS/KEV data
--cache-db      Cache database path (default: epss_cache.db)
--output-prefix Custom output filename prefix
--config        Config file (default: prioritizer_config.json)
```

## How It Works

The system calculates risk scores based on:

1. **CVSS Score** - Base vulnerability severity
2. **EPSS Score** - Exploitation probability from FIRST.org
3. **Asset Context** - Criticality, exposure, data sensitivity
4. **CISA KEV** - Known exploited vulnerabilities
5. **Temporal Factors** - Age of vulnerability

### Asset Criticality

Reads criticality from source data (Qualys uses 1-5 scale):
- 5 = Critical production systems
- 4 = High importance systems
- 3 = Standard systems
- 2 = Low priority systems
- 1 = Dev/Test environments

### Risk Levels

- **CRITICAL** (80-100) - Immediate action required
- **HIGH** (60-79) - Patch within 7 days
- **MEDIUM** (40-59) - Patch within 30 days
- **LOW** (20-39) - Patch within 90 days
- **MINIMAL** (0-19) - Schedule with routine maintenance

## Configuration

Edit `prioritizer_config.json` to adjust:

```json
{
  "prioritization_weights": {
    "cvss_weight": 0.15,
    "epss_weight": 0.30,
    "asset_context_weight": 0.25,
    "threat_intel_weight": 0.25,
    "temporal_weight": 0.05
  }
}
```

### Override Conditions

Vulnerabilities automatically promote to CRITICAL when meeting specific criteria:
- High CVSS + High EPSS + CISA KEV
- Critical asset + High CVSS + exploitation evidence
- Internet-facing + High CVSS + known exploit

## Output

Generates two files:
- `*_prioritized.csv` - Spreadsheet format
- `*_prioritized.json` - JSON for APIs/dashboards

## Examples

```bash
# Basic scan
python3 run_prioritizer.py --source qualys vulnerabilities.csv

# Top 50 with fresh data
python3 run_prioritizer.py --source qualys --top-n 50 --no-cache scan.csv

# Custom output name
python3 run_prioritizer.py --source nessus --output-prefix datacenter scan.nessus
```

## API Requirements

The system fetches data from:
- EPSS API: https://api.first.org/data/v1/epss
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Both APIs are public and don't require authentication.

## Troubleshooting

**No results**: Check that your scan file contains CVE identifiers.

**API errors**: System works offline but with reduced accuracy. Check network access to api.first.org and cisa.gov.

**Memory issues**: For large scans (>10k vulnerabilities), increase Python heap size.

## License

MIT
