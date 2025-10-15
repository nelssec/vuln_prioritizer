#!/usr/bin/env python3
"""
Vulnerability Prioritizer Runner v3
Supports multiple data sources: Nessus, Tenable, Qualys, etc.
"""

import sys
import os
import argparse

def main():
    print("="*70)
    print(" VULNERABILITY PRIORITIZATION SYSTEM v3")
    print(" EPSS Scoring + CISA KEV + Database Caching")
    print("="*70)
    print()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Vulnerability Prioritization System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 run_prioritizer_v3.py --source nessus scan.nessus
  python3 run_prioritizer_v3.py --source tenable tenable_export.nessus
  python3 run_prioritizer_v3.py --source qualys qualys_scan.xml
  python3 run_prioritizer_v3.py --source nessus --no-cache scan.nessus

Data Sources:
  nessus   - Nessus .nessus XML format
  tenable  - Tenable .nessus XML format
  qualys   - Qualys XML format
        '''
    )
    
    parser.add_argument(
        '--source',
        choices=['nessus', 'tenable', 'qualys'],
        default='nessus',
        help='Data source type (default: nessus)'
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        help='Input scan file'
    )
    
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable database caching'
    )
    
    parser.add_argument(
        '--cache-db',
        default='epss_cache.db',
        help='Path to cache database (default: epss_cache.db)'
    )
    
    parser.add_argument(
        '--output-prefix',
        help='Output file prefix (default: based on input filename)'
    )
    
    parser.add_argument(
        '--top-n',
        type=int,
        default=20,
        help='Number of top vulnerabilities to display (default: 20)'
    )
    
    args = parser.parse_args()
    
    # Determine input file
    if args.input_file:
        input_file = args.input_file
    else:
        # Use mock data for demo
        input_file = "mock_nessus_scan.nessus"
        if not os.path.exists(input_file):
            print("[ERROR] No input file specified and mock_nessus_scan.nessus not found")
            print()
            print("Usage:")
            print("  python3 run_prioritizer_v3.py --source nessus scan.nessus")
            print()
            parser.print_help()
            return 1
    
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file not found: {input_file}")
        return 1
    
    print(f"[INPUT] File: {input_file}")
    print(f"[SOURCE] Type: {args.source}")
    print(f"[CACHE] Database: {args.cache_db} (enabled: {not args.no_cache})")
    print()
    
    # Import prioritizer
    from vulnerability_prioritizer_v3 import VulnerabilityPrioritizer, DataSource
    
    # Initialize
    print("[INFO] Initializing prioritizer...")
    prioritizer = VulnerabilityPrioritizer(
        use_cache=not args.no_cache,
        cache_db_path=args.cache_db
    )
    print()
    
    # Import vulnerabilities based on source
    print(f"[INFO] Importing vulnerabilities from {args.source} source...")
    
    if args.source == 'nessus':
        vulns = prioritizer.import_nessus(input_file)
    elif args.source == 'tenable':
        vulns = prioritizer.import_tenable(input_file)
    elif args.source == 'qualys':
        vulns = prioritizer.import_qualys(input_file)
    else:
        print(f"[ERROR] Unsupported source: {args.source}")
        return 1
    
    if not vulns:
        print("[ERROR] No vulnerabilities found in scan")
        return 1
    
    print()
    
    # Prioritize
    print("[INFO] Prioritizing vulnerabilities...")
    results = prioritizer.prioritize_vulnerabilities(vulns)
    print()
    
    # Determine output filenames
    if args.output_prefix:
        base_name = args.output_prefix
    else:
        base_name = os.path.splitext(input_file)[0]
    
    csv_file = f"{base_name}_prioritized.csv"
    json_file = f"{base_name}_prioritized.json"
    
    # Export
    prioritizer.export_to_csv(results, csv_file)
    prioritizer.export_to_json(results, json_file)
    print()
    
    # Generate report
    print("="*70)
    print(" PRIORITIZATION REPORT")
    print("="*70)
    print()
    report = prioritizer.generate_report(results, top_n=args.top_n)
    print(report)
    
    # Statistics
    epss_scores = [v.epss_score for v in results if v.epss_score and v.epss_score > 0]
    cisa_kev_count = len([v for v in results if v.in_cisa_kev])
    
    print()
    print("="*70)
    print(" THREAT INTELLIGENCE SUMMARY")
    print("="*70)
    print()
    print(f"Total Unique CVEs: {len(results)}")
    print(f"CVEs with EPSS scores: {len(epss_scores)}/{len(results)} ({len(epss_scores)/len(results)*100:.1f}%)")
    print(f"CVEs in CISA KEV: {cisa_kev_count} ({cisa_kev_count/len(results)*100:.1f}%)")
    
    if epss_scores:
        print()
        print(f"EPSS Score Statistics:")
        print(f"  Average: {sum(epss_scores)/len(epss_scores):.4f} ({sum(epss_scores)/len(epss_scores)*100:.2f}%)")
        print(f"  Maximum: {max(epss_scores):.4f} ({max(epss_scores)*100:.2f}%)")
        print(f"  Median:  {sorted(epss_scores)[len(epss_scores)//2]:.4f}")
        
        print()
        print("Exploitation Probability Distribution:")
        print(f"  Very High (>50%):  {len([s for s in epss_scores if s > 0.5])} CVEs")
        print(f"  High (10-50%):     {len([s for s in epss_scores if 0.1 < s <= 0.5])} CVEs")
        print(f"  Medium (1-10%):    {len([s for s in epss_scores if 0.01 < s <= 0.1])} CVEs")
        print(f"  Low (<1%):         {len([s for s in epss_scores if 0 < s <= 0.01])} CVEs")
    
    print()
    print("Risk Level Distribution:")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']:
        count = len([v for v in results if v.risk_level.value == level])
        pct = (count/len(results)*100) if results else 0
        print(f"  {level:8s}: {count:3d} ({pct:5.1f}%)")
    
    # Cache statistics
    if not args.no_cache:
        prioritizer.print_cache_stats()
    
    print()
    print("="*70)
    print(" OUTPUT FILES")
    print("="*70)
    print()
    print(f"[CSV]  {csv_file}")
    print(f"[JSON] {json_file}")
    print()
    print("Next steps:")
    print(f"  1. Review {csv_file} in Excel/spreadsheet")
    print(f"  2. Load {json_file} in vulnerability dashboard")
    print("  3. Focus patching on CRITICAL and HIGH priority items")
    print()
    print("[SUCCESS] PRIORITIZATION COMPLETE")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
