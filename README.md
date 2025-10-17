# Vulnerability Prioritizer

Drop-in replacement for vulnerability prioritization with improved risk scoring for critical assets.

## Installation

```bash
# Replace existing files
cp vulnerability_prioritizer.py run_prioritizer.py prioritizer_config.json /path/to/vuln_prioritizer/
```

Dependencies:
```bash
pip install requests
```

## Usage

```bash
# Qualys CSV
python3 run_prioritizer.py --source qualys scan.csv

# Nessus
python3 run_prioritizer.py --source nessus scan.nessus

# Tenable
python3 run_prioritizer.py --source tenable export.nessus
```

## Options

```
--source        Data source type (nessus/tenable/qualys)
--top-n         Number of top vulnerabilities to display
--no-cache      Disable database caching
--cache-db      Path to cache database
--config        Configuration file path
--output-prefix Custom output file prefix
```

## Configuration

Edit `prioritizer_config.json`:

- **prioritization_weights**: Adjust importance of different factors
- **asset_classification**: Define critical asset patterns
- **critical_override_conditions**: Automatic promotion thresholds
- **api_settings**: EPSS and CISA KEV API endpoints
- **cache_settings**: Cache expiration times

## Asset Criticality Mapping

| Score | Level    | Description                |
|-------|----------|----------------------------|
| 5     | CRITICAL | Mission-critical systems   |
| 4     | HIGH     | Important production       |
| 3     | MEDIUM   | Standard systems          |
| 2     | LOW      | Non-critical             |
| 1     | MINIMAL  | Dev/QA environments      |

## Risk Scoring

The system calculates risk based on:
- CVSS base score
- EPSS exploitation probability
- Asset criticality and exposure
- CISA Known Exploited Vulnerabilities
- Temporal factors

Override conditions automatically promote high-risk combinations to CRITICAL.

## Output

- CSV file: `<input>_prioritized.csv`
- JSON file: `<input>_prioritized.json`

## Performance

First run fetches EPSS/KEV data from APIs. Subsequent runs use cached data for better performance.

Cache expiration:
- EPSS: 7 days
- CISA KEV: 1 day

## Compatibility

Works with existing integrations from https://github.com/nelssec/vuln_prioritizer
