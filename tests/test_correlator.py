#!/usr/bin/env python3

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connectors.base import NormalizedVulnerability
from engine.correlator import VulnerabilityCorrelator


class TestVulnerabilityCorrelator(unittest.TestCase):
    def setUp(self):
        self.correlator = VulnerabilityCorrelator()

    def test_same_cve_from_two_scanners_merges(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-1234", asset_ip="10.0.0.1",
                cvss_score=7.5, source="nessus", source_confidence=0.9,
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-1234", asset_ip="10.0.0.1",
                cvss_score=8.0, source="qualys", source_confidence=0.85,
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].cve_id, "CVE-2024-1234")
        # Source should be merged
        self.assertIn("nessus", result[0].source)
        self.assertIn("qualys", result[0].source)

    def test_conflicting_cvss_resolves_to_highest(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-5678", asset_ip="10.0.0.2",
                cvss_score=6.5, source="scanner_a",
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-5678", asset_ip="10.0.0.2",
                cvss_score=9.8, source="scanner_b",
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].cvss_score, 9.8)

    def test_kev_from_any_source_propagates(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-9999", asset_ip="10.0.0.3",
                in_kev=False, source="scanner_a",
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-9999", asset_ip="10.0.0.3",
                in_kev=True, source="kev_enriched",
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].in_kev)

    def test_epss_weighted_average(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-1111", asset_ip="10.0.0.4",
                epss_score=0.5, source="a", source_confidence=0.8,
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-1111", asset_ip="10.0.0.4",
                epss_score=0.3, source="b", source_confidence=0.2,
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertEqual(len(result), 1)
        # Weighted average: (0.5*0.8 + 0.3*0.2) / (0.8+0.2) = 0.46
        self.assertAlmostEqual(result[0].epss_score, 0.46, places=2)

    def test_different_assets_not_merged(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-2222", asset_ip="10.0.0.1", source="a",
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-2222", asset_ip="10.0.0.2", source="a",
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertEqual(len(result), 2)

    def test_lists_deduplicated(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-3333", asset_ip="10.0.0.5",
                cwe_ids=["CWE-79", "CWE-89"], references=["https://example.com"],
                source="a",
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-3333", asset_ip="10.0.0.5",
                cwe_ids=["CWE-89", "CWE-200"], references=["https://example.com", "https://other.com"],
                source="b",
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0].cwe_ids), 3)  # CWE-79, CWE-89, CWE-200
        self.assertEqual(len(result[0].references), 2)

    def test_exploit_available_or(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-4444", asset_ip="10.0.0.6",
                exploit_available=False, source="a",
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-4444", asset_ip="10.0.0.6",
                exploit_available=True, source="b",
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertTrue(result[0].exploit_available)

    def test_source_confidence_averaged(self):
        vulns = [
            NormalizedVulnerability(
                cve_id="CVE-2024-5555", asset_ip="10.0.0.7",
                source_confidence=0.9, source="a",
            ),
            NormalizedVulnerability(
                cve_id="CVE-2024-5555", asset_ip="10.0.0.7",
                source_confidence=0.7, source="b",
            ),
        ]
        result = self.correlator.correlate(vulns)
        self.assertAlmostEqual(result[0].source_confidence, 0.8, places=2)


if __name__ == "__main__":
    unittest.main()
