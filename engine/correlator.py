#!/usr/bin/env python3

from typing import Dict, List, Tuple

from connectors.base import NormalizedVulnerability


class VulnerabilityCorrelator:
    def correlate(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        """Merge vulnerabilities by (cve_id, asset_ip) key."""
        merged: Dict[Tuple[str, str], NormalizedVulnerability] = {}

        for vuln in vulns:
            key = (vuln.cve_id, vuln.asset_ip)

            if key not in merged:
                merged[key] = NormalizedVulnerability(
                    cve_id=vuln.cve_id,
                    asset_ip=vuln.asset_ip,
                    asset_hostname=vuln.asset_hostname,
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score,
                    cvss_v4_score=vuln.cvss_v4_score,
                    epss_score=vuln.epss_score,
                    in_kev=vuln.in_kev,
                    exploit_available=vuln.exploit_available,
                    patch_available=vuln.patch_available,
                    source=vuln.source,
                    source_confidence=vuln.source_confidence,
                    cloud_metadata=dict(vuln.cloud_metadata),
                    threat_actor_campaigns=list(vuln.threat_actor_campaigns),
                    cwe_ids=list(vuln.cwe_ids),
                    description=vuln.description,
                    references=list(vuln.references),
                )
            else:
                existing = merged[key]
                self._merge_into(existing, vuln)

        return list(merged.values())

    def _merge_into(self, existing: NormalizedVulnerability, new: NormalizedVulnerability):
        # CVSS: take maximum
        existing.cvss_score = max(existing.cvss_score, new.cvss_score)

        if new.cvss_v4_score is not None:
            if existing.cvss_v4_score is not None:
                existing.cvss_v4_score = max(existing.cvss_v4_score, new.cvss_v4_score)
            else:
                existing.cvss_v4_score = new.cvss_v4_score

        # Booleans: OR
        existing.in_kev = existing.in_kev or new.in_kev
        existing.exploit_available = existing.exploit_available or new.exploit_available
        if new.patch_available is not None:
            existing.patch_available = (existing.patch_available or False) or new.patch_available

        # EPSS: weighted average by source_confidence
        if new.epss_score is not None:
            if existing.epss_score is not None:
                total_weight = existing.source_confidence + new.source_confidence
                if total_weight > 0:
                    existing.epss_score = (
                        existing.epss_score * existing.source_confidence +
                        new.epss_score * new.source_confidence
                    ) / total_weight
            else:
                existing.epss_score = new.epss_score

        # Lists: union/deduplicate
        existing.threat_actor_campaigns = list(set(existing.threat_actor_campaigns + new.threat_actor_campaigns))
        existing.cwe_ids = list(set(existing.cwe_ids + new.cwe_ids))
        existing.references = list(set(existing.references + new.references))

        # Cloud metadata: merge dicts
        existing.cloud_metadata.update(new.cloud_metadata)

        # Source confidence: average
        existing.source_confidence = (existing.source_confidence + new.source_confidence) / 2

        # Keep better hostname
        if not existing.asset_hostname and new.asset_hostname:
            existing.asset_hostname = new.asset_hostname

        # Keep better description
        if not existing.description and new.description:
            existing.description = new.description

        # Use highest severity
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "": 0}
        if severity_order.get(new.severity, 0) > severity_order.get(existing.severity, 0):
            existing.severity = new.severity

        # Track merged source
        if new.source and new.source not in existing.source:
            existing.source = f"{existing.source},{new.source}"
