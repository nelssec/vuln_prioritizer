#!/usr/bin/env python3

from vulnerability_prioritizer import VulnerabilityPrioritizer, DataSource

# Initialize the prioritizer
prioritizer = VulnerabilityPrioritizer()

# Test the generic CSV parser
print("=" * 80)
print("Testing Generic CSV Parser")
print("=" * 80)

vulnerabilities = prioritizer.import_generic_csv('test_sample.csv')

if vulnerabilities:
    print(f"\n✓ Successfully parsed {len(vulnerabilities)} vulnerabilities!")

    print("\n" + "=" * 80)
    print("Sample Vulnerabilities:")
    print("=" * 80)

    for i, vuln in enumerate(vulnerabilities[:5], 1):
        print(f"\n#{i} {vuln.cve_id}")
        print(f"  CVSS Score: {vuln.cvss_score}")
        print(f"  Asset Criticality: {vuln.asset_criticality.name}")
        print(f"  Business Unit: {vuln.business_unit}")
        print(f"  Asset Tags: {vuln.asset_tags}")
        print(f"  Asset Owner: {vuln.asset_owner}")
        print(f"  Affected Assets: {', '.join(vuln.affected_assets)}")

    # Test prioritization
    print("\n" + "=" * 80)
    print("Running Prioritization (may take a moment...)")
    print("=" * 80)

    prioritized = prioritizer.prioritize_vulnerabilities(vulnerabilities)

    print("\n" + "=" * 80)
    print("Top 5 Prioritized Vulnerabilities:")
    print("=" * 80)

    for vuln in prioritized[:5]:
        print(f"\nRank #{vuln.priority_rank}: {vuln.cve_id}")
        print(f"  Risk Score: {vuln.risk_score:.1f}/100 ({vuln.risk_level.value})")
        print(f"  CVSS: {vuln.cvss_score:.1f}")
        print(f"  Business Unit: {vuln.business_unit or 'N/A'}")
        print(f"  Tags: {', '.join(vuln.asset_tags) if vuln.asset_tags else 'N/A'}")

    # Export to JSON for testing with the dashboard
    prioritizer.export_to_json(prioritized, 'test_prioritized.json')
    print("\n✓ Exported to test_prioritized.json")
    print("✓ You can now load this file in the HTML dashboard!")

else:
    print("\n✗ Failed to parse vulnerabilities")
