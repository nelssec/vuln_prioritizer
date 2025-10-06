# Context-Aware Vulnerability Prioritization System

## Overview

This vulnerability prioritization system demonstrates why **CVSS alone isn't enough** for effective patch management. It combines multiple data sources and business context to create actionable prioritization that reflects real-world risk.

## Key Features

### Multi-Source Intelligence Integration
- **CVSS Scores** - Base vulnerability severity (v2, v3, v4)
- **EPSS** (Exploit Prediction Scoring System) - Probability of exploitation
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **Threat Intelligence** - Active exploitation, ransomware campaigns, APT activity
- **Business Context** - Asset criticality, data sensitivity, network exposure

### Smart Risk Scoring Algorithm

The system uses a weighted scoring model:
- **20%** - CVSS Base Score
- **25%** - EPSS Probability  
- **20%** - Asset Context (criticality, exposure, data sensitivity)
- **25%** - Threat Intelligence
- **10%** - Temporal Factors

## Why This Matters

### Traditional CVSS-Only Approach:
```
1. CVE-2024-12345: CVSS 9.8 (CRITICAL) ← Patch first?
2. CVE-2024-89012: CVSS 8.8 (HIGH)
3. CVE-2024-23456: CVSS 8.5 (HIGH)
```

### Context-Aware Prioritization:
```
1. CVE-2024-12345: Risk 94.3/100 (CRITICAL) 
   → Internet-facing, exploited in wild, customer data
2. CVE-2024-23456: Risk 78.5/100 (HIGH)
   → Database server, exploit available, PII data
3. CVE-2024-89012: Risk 12.4/100 (LOW)
   → Legacy system, isolated network, compensating controls
```

## Getting Started

### Installation

```bash
# Install required packages
pip install requests --break-system-packages

# Clone or download the files
# - vulnerability_prioritizer.py
# - prioritizer_config.json
# - vulnerability_dashboard.html
```

### Basic Usage

```python
# Run the prioritizer
python3 vulnerability_prioritizer.py

# This will:
# 1. Load vulnerability data
# 2. Fetch threat intelligence
# 3. Calculate risk scores
# 4. Generate prioritized report
# 5. Export to CSV
```

### View Dashboard

Open `vulnerability_dashboard.html` in your browser to see:
- Visual priority distribution
- Patch timeline tracking
- Detailed vulnerability cards with risk factors
- SLA compliance metrics

## Configuration

Edit `prioritizer_config.json` to customize:

### Adjust Scoring Weights
```json
"prioritization_weights": {
    "cvss_weight": 0.20,      # Reduce if CVSS overweighted
    "epss_weight": 0.25,      # Increase for exploit focus
    "asset_context_weight": 0.20,
    "threat_intel_weight": 0.25,
    "temporal_weight": 0.10
}
```

### Define Asset Criticality
```json
"asset_classification": {
    "critical_indicators": ["prod", "payment", "customer"],
    "internet_facing_multiplier": 2.0,
    "data_sensitivity_multiplier": 1.5
}
```

### Set Patch SLAs
```json
"patch_management": {
    "critical_sla_hours": 24,
    "high_sla_hours": 168,
    "medium_sla_hours": 720
}
```

## Integration

### Input Sources

The system can integrate with:
- **Vulnerability Scanners** (Nessus, Qualys, Rapid7)
- **SIEM/SOAR** platforms
- **Asset Management** systems (ServiceNow, Lansweeper)
- **Threat Intelligence** feeds (MISP, ThreatConnect)

### API Integration Example

```python
from vulnerability_prioritizer import VulnerabilityPrioritizer, Vulnerability

# Initialize
prioritizer = VulnerabilityPrioritizer()

# Create vulnerability from scan data
vuln = Vulnerability(
    cve_id="CVE-2024-99999",
    cvss_score=7.5,
    affected_assets=["web-server-01"],
    asset_criticality=AssetCriticality.CRITICAL,
    exposure_level=ExposureLevel.INTERNET
)

# Get prioritization
prioritized = prioritizer.prioritize_vulnerabilities([vuln])
```

### Output Formats

- **CSV** - For spreadsheet analysis
- **JSON** - For API integration  
- **HTML** - For reporting
- **Webhook** - For alerting

## Metrics & KPIs

Track improvement with:
- **Mean Time to Remediation (MTTR)** by priority
- **SLA Compliance** rates
- **False Positive** reduction
- **Risk Score** accuracy vs actual exploitations

## Key Concepts Explained

### CVSS Limitations
- **Static scoring** - Doesn't change based on your environment
- **No threat context** - Same score whether actively exploited or not
- **Version inconsistencies** - v2 vs v3 vs v4 differences
- **Missing business impact** - Treats all assets equally

### EPSS Advantages
- **Predictive** - Estimates exploitation probability
- **Dynamic** - Updates based on threat landscape
- **Evidence-based** - Uses real exploitation data
- **Percentile ranking** - Compare relative risk

### Business Context Factors
- **Asset Criticality** - Revenue impact, customer-facing
- **Data Sensitivity** - PII, PHI, trade secrets
- **Network Exposure** - Internet, extranet, internal
- **Compensating Controls** - WAF, segmentation, monitoring

## Customization

### Add Custom Threat Feeds

```python
def fetch_custom_intel(self, cve_id):
    # Your threat intel API
    response = requests.get(f"https://your-api.com/cve/{cve_id}")
    return response.json()
```

### Implement Asset Discovery

```python
def discover_assets(self):
    # Query your CMDB/asset management
    assets = cmdb_api.get_assets()
    return self.classify_assets(assets)
```

### Create Custom Reports

```python
def generate_executive_report(self, vulns):
    # Custom formatting for leadership
    report = self.build_executive_summary(vulns)
    self.send_to_executives(report)
```

## Best Practices

1. **Regular Updates** - Refresh threat intel daily
2. **Asset Classification** - Keep criticality current
3. **Validate Scores** - Compare predictions to actual incidents
4. **Iterate Weights** - Adjust based on your environment
5. **Document Decisions** - Track why priorities changed

## Security Considerations

- **API Keys** - Store securely, rotate regularly
- **Data Privacy** - Anonymize asset names if needed
- **Access Control** - Limit who can modify weights
- **Audit Trail** - Log all prioritization changes

## Sample Output

```
VULNERABILITY PRIORITIZATION REPORT
=====================================
Total Vulnerabilities: 147
  CRITICAL: 12 (8%)
  HIGH: 28 (19%)
  MEDIUM: 45 (31%)
  LOW: 52 (35%)
  MINIMAL: 10 (7%)

TOP PRIORITY (Patch within 24 hours):
1. CVE-2024-12345 [Risk: 94.3/100]
   - Remote code execution
   - 3 critical assets affected
   - Exploited in wild
   - Internet-facing
   
Recommended Action:
→ Emergency patch window tonight
→ Apply WAF rules immediately
→ Monitor for exploitation attempts
```

## Contributing

This is a demonstration system. In production, you would:
- Add real threat intelligence APIs
- Integrate with your vulnerability scanners
- Connect to asset management systems
- Implement automated patching workflows

## License

This demonstration code is provided as-is for educational purposes.

## Support

For questions about the vulnerability prioritization methodology:
- Review FIRST EPSS documentation
- Consult CISA KEV catalog
- Reference NIST CVSS specifications

---

**Remember:** Effective vulnerability management requires combining technical scoring (CVSS) with business context, threat intelligence, and operational constraints. This system demonstrates that holistic approach.
