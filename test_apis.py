#!/usr/bin/env python3
"""
Test EPSS API Implementation
Verifies correct API endpoint and response parsing
"""

import requests
import json
from datetime import datetime

def test_epss_api():
    """Test the EPSS API endpoint"""
    print("="*60)
    print("TESTING EPSS API IMPLEMENTATION")
    print("="*60)
    print()
    
    # Test CVEs
    test_cves = [
        "CVE-2024-3094",  # XZ Utils backdoor
        "CVE-2023-46604", # Apache ActiveMQ
        "CVE-2024-21762"  # Fortinet
    ]
    
    print(f"[TEST] Testing with {len(test_cves)} CVEs")
    print(f"[CVEs] {', '.join(test_cves)}")
    print()
    
    # Single CVE test
    print("[TEST 1] Single CVE query...")
    url_single = f"https://api.first.org/data/v1/epss?cve={test_cves[0]}"
    print(f"[URL] {url_single}")
    
    try:
        response = requests.get(url_single, timeout=10)
        print(f"[STATUS] {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"[SUCCESS] Single CVE query successful")
            print(f"[MODEL] {data.get('model-version', 'N/A')}")
            print(f"[DATE] {data.get('score-date', 'N/A')}")
            
            if data.get('data'):
                cve_data = data['data'][0]
                print(f"[CVE] {cve_data['cve']}")
                print(f"[EPSS] {cve_data['epss']}")
                print(f"[PERCENTILE] {cve_data['percentile']}")
        else:
            print(f"[ERROR] Failed with status {response.status_code}")
            print(f"[RESPONSE] {response.text[:200]}")
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
    
    print()
    
    # Batch CVE test
    print("[TEST 2] Batch CVE query...")
    url_batch = f"https://api.first.org/data/v1/epss?cve={','.join(test_cves)}"
    print(f"[URL] {url_batch}")
    
    try:
        response = requests.get(url_batch, timeout=10)
        print(f"[STATUS] {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"[SUCCESS] Batch query successful")
            print(f"[TOTAL] {data.get('total', 0)} CVEs returned")
            print(f"[MODEL] {data.get('model-version', 'N/A')}")
            print(f"[DATE] {data.get('score-date', 'N/A')}")
            print()
            
            if data.get('data'):
                print("[RESULTS]")
                for item in data['data']:
                    epss_pct = float(item['epss']) * 100
                    print(f"  {item['cve']}: EPSS={epss_pct:.2f}%, Percentile={float(item['percentile']):.1f}%")
        else:
            print(f"[ERROR] Failed with status {response.status_code}")
            print(f"[RESPONSE] {response.text[:200]}")
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
    
    print()
    print("="*60)
    print("[INFO] EPSS API test complete")
    print("="*60)


def test_cisa_kev_api():
    """Test the CISA KEV API endpoint"""
    print()
    print("="*60)
    print("TESTING CISA KEV API")
    print("="*60)
    print()
    
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print(f"[URL] {url}")
    
    try:
        response = requests.get(url, timeout=10)
        print(f"[STATUS] {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            print(f"[SUCCESS] CISA KEV query successful")
            print(f"[TITLE] {data.get('title', 'N/A')}")
            print(f"[COUNT] {data.get('count', 0)} vulnerabilities")
            
            if vulns:
                print()
                print("[SAMPLE] First 3 entries:")
                for vuln in vulns[:3]:
                    print(f"  {vuln['cveID']}: {vuln.get('vulnerabilityName', 'N/A')}")
        else:
            print(f"[ERROR] Failed with status {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
    
    print()
    print("="*60)
    print("[INFO] CISA KEV API test complete")
    print("="*60)


if __name__ == "__main__":
    test_epss_api()
    test_cisa_kev_api()
    print()
    print("[SUCCESS] All API tests complete")
