#!/usr/bin/env python3

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connectors.scanners.qualys_csv import QualysCSVConnector
from engine.correlator import VulnerabilityCorrelator
from engine.scorer import VulnerabilityScorer


class TestIntegration(unittest.TestCase):
    """Integration tests using test_sample.csv through the new connector stack."""

    def setUp(self):
        self.test_csv = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "test_sample.csv"
        )
        self.connector = QualysCSVConnector()
        self.correlator = VulnerabilityCorrelator()
        self.scorer = VulnerabilityScorer()

    def test_parse_test_sample(self):
        """Verify test_sample.csv parses correctly through connector."""
        vulns = self.connector.parse(self.test_csv)
        self.assertGreater(len(vulns), 0)
        # test_sample.csv has 10 rows with 10 unique CVEs
        self.assertEqual(len(vulns), 10)

    def test_all_cves_present(self):
        """Verify all expected CVEs are found."""
        vulns = self.connector.parse(self.test_csv)
        cve_ids = {v.cve_id for v in vulns}
        expected = {
            "CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9012",
            "CVE-2024-3456", "CVE-2024-7890", "CVE-2023-1111",
            "CVE-2024-2222", "CVE-2024-3333", "CVE-2024-4444",
            "CVE-2024-5555",
        }
        self.assertEqual(cve_ids, expected)

    def test_cvss_scores_parsed(self):
        """Verify CVSS scores are correctly parsed."""
        vulns = self.connector.parse(self.test_csv)
        cvss_map = {v.cve_id: v.cvss_score for v in vulns}
        self.assertEqual(cvss_map["CVE-2024-1234"], 9.8)
        self.assertEqual(cvss_map["CVE-2024-5678"], 8.5)
        self.assertEqual(cvss_map["CVE-2024-3456"], 5.5)

    def test_correlator_no_change_unique(self):
        """Correlator should not merge unique CVE+asset pairs."""
        vulns = self.connector.parse(self.test_csv)
        correlated = self.correlator.correlate(vulns)
        self.assertEqual(len(correlated), len(vulns))

    def test_scorer_default_profile(self):
        """Scorer should produce scores for all vulns."""
        vulns = self.connector.parse(self.test_csv)
        scored = self.scorer.score_all(vulns, profile="default")
        self.assertEqual(len(scored), len(vulns))
        # All scores should be between 0 and 100
        for vuln, score in scored:
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)

    def test_scorer_critical_vuln_higher(self):
        """Higher CVSS should produce higher score (all else equal)."""
        vulns = self.connector.parse(self.test_csv)
        scored = self.scorer.score_all(vulns, profile="default")
        score_map = {vuln.cve_id: score for vuln, score in scored}
        # CVE-2024-1234 (CVSS 9.8) should score higher than CVE-2024-3456 (CVSS 5.5)
        self.assertGreater(score_map["CVE-2024-1234"], score_map["CVE-2024-3456"])

    def test_scorer_oss_library_profile(self):
        """oss_library profile should work without errors."""
        vulns = self.connector.parse(self.test_csv)
        scored = self.scorer.score_all(vulns, profile="oss_library")
        self.assertEqual(len(scored), len(vulns))

    def test_scorer_cloud_workload_profile(self):
        """cloud_workload profile should work without errors."""
        vulns = self.connector.parse(self.test_csv)
        scored = self.scorer.score_all(vulns, profile="cloud_workload")
        self.assertEqual(len(scored), len(vulns))

    def test_legacy_prioritizer_backward_compat(self):
        """Verify the legacy VulnerabilityPrioritizer API still works."""
        from vulnerability_prioritizer import VulnerabilityPrioritizer

        # Use no-cache to avoid network calls
        prioritizer = VulnerabilityPrioritizer(
            config_file="nonexistent_config.json",
            use_cache=False,
        )
        vulns = prioritizer.import_qualys(self.test_csv)
        self.assertGreater(len(vulns), 0)
        # Verify they are proper Vulnerability objects with expected fields
        for vuln in vulns:
            self.assertTrue(vuln.cve_id.startswith("CVE-"))
            self.assertGreater(vuln.cvss_score, 0)

    def test_scored_results_sorted_descending(self):
        """score_all should return results sorted by score descending."""
        vulns = self.connector.parse(self.test_csv)
        scored = self.scorer.score_all(vulns, profile="default")
        scores = [score for _, score in scored]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main()
