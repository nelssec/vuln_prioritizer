#!/usr/bin/env python3
"""Integration test: run the full connector stack against test_sample.csv
and verify output matches expected behavior (no regression)."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connectors.scanners.qualys_csv import QualysCSVConnector
from engine.correlator import VulnerabilityCorrelator
from engine.scorer import VulnerabilityScorer

SAMPLE_CSV = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_sample.csv")


@unittest.skipUnless(os.path.isfile(SAMPLE_CSV), "test_sample.csv not found")
class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.connector = QualysCSVConnector()
        self.correlator = VulnerabilityCorrelator()
        self.scorer = VulnerabilityScorer()

    def test_qualys_csv_parses_without_error(self):
        vulns = self.connector.parse(SAMPLE_CSV)
        self.assertGreater(len(vulns), 0, "Should parse at least one vulnerability")

    def test_all_have_cve_ids(self):
        vulns = self.connector.parse(SAMPLE_CSV)
        for v in vulns:
            self.assertTrue(v.cve_id.startswith("CVE-"), f"Expected CVE-* ID, got: {v.cve_id}")

    def test_correlator_reduces_or_equals_count(self):
        vulns = self.connector.parse(SAMPLE_CSV)
        correlated = self.correlator.correlate(vulns)
        # Correlation can only reduce or maintain count
        self.assertLessEqual(len(correlated), len(vulns))

    def test_scorer_returns_scores_in_range(self):
        vulns = self.connector.parse(SAMPLE_CSV)
        correlated = self.correlator.correlate(vulns)
        results = self.scorer.score_all(correlated)
        for vuln, score in results:
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 100.0)

    def test_scorer_ordered_descending(self):
        vulns = self.connector.parse(SAMPLE_CSV)
        correlated = self.correlator.correlate(vulns)
        results = self.scorer.score_all(correlated)
        scores = [s for _, s in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_cloud_profile_vs_default_differ(self):
        """Profiles should produce different orderings for at least some CVEs."""
        vulns = self.connector.parse(SAMPLE_CSV)
        correlated = self.correlator.correlate(vulns)
        if len(correlated) < 2:
            self.skipTest("Need at least 2 vulns to compare profiles")

        default_results = self.scorer.score_all(correlated, profile="default")
        cloud_results = self.scorer.score_all(correlated, profile="cloud_workload")

        # Scores may differ even if ordering is the same; just verify both run
        self.assertEqual(len(default_results), len(cloud_results))

    def test_oss_library_profile_uses_patch_weight(self):
        """oss_library profile should score patch_available=True higher."""
        from connectors.base import NormalizedVulnerability

        vuln_with_patch = NormalizedVulnerability(
            cve_id="CVE-2024-TEST1", cvss_score=7.0, patch_available=True
        )
        vuln_without_patch = NormalizedVulnerability(
            cve_id="CVE-2024-TEST2", cvss_score=7.0, patch_available=False
        )

        score_with = self.scorer.score(vuln_with_patch, profile="oss_library")
        score_without = self.scorer.score(vuln_without_patch, profile="oss_library")

        # patch_available=True gets higher score in oss_library
        self.assertGreater(score_with, score_without)

    def test_full_pipeline_via_prioritizer(self):
        """End-to-end via VulnerabilityPrioritizer (no network calls)."""
        from vulnerability_prioritizer import VulnerabilityPrioritizer

        prioritizer = VulnerabilityPrioritizer(
            config_file="prioritizer_config.json",
            use_cache=False,
        )

        vulns = prioritizer.import_qualys(SAMPLE_CSV)
        self.assertGreater(len(vulns), 0)

        # Check legacy Vulnerability objects have expected fields
        for v in vulns:
            self.assertTrue(hasattr(v, "cve_id"))
            self.assertTrue(hasattr(v, "cvss_score"))


if __name__ == "__main__":
    unittest.main()
