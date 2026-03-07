#!/usr/bin/env python3

import csv
from typing import Any, List

from connectors.base import NormalizedVulnerability, ScannerConnector


class BlackDuckConnector(ScannerConnector):
    def supported_formats(self) -> List[str]:
        return ["csv", "json"]

    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        """Parse BlackDuck SCA CSV export. data is a filepath string."""
        vulnerabilities = []

        with open(data, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            headers_lower = [h.lower().strip() for h in headers]

            col_map = _detect_blackduck_columns(headers, headers_lower)
            if "cve_id" not in col_map:
                return []

            for row in reader:
                cve_raw = row.get(col_map["cve_id"], "").strip()
                cve_ids = [c.strip() for c in cve_raw.replace(";", ",").split(",") if c.strip().startswith("CVE-")]
                if not cve_ids:
                    continue

                component = row.get(col_map.get("component", ""), "").strip() or "Unknown"
                version = row.get(col_map.get("version", ""), "").strip()
                asset_name = f"{component}:{version}" if version else component

                cvss_score = 5.0
                if "cvss_score" in col_map:
                    try:
                        cvss_score = float(row.get(col_map["cvss_score"], "0").strip())
                    except (ValueError, TypeError):
                        pass

                description = row.get(col_map.get("description", ""), "").strip()[:200]

                remediation = row.get(col_map.get("remediation", ""), "").strip()
                patch_available = bool(remediation)

                for cve_id in cve_ids:
                    vulnerabilities.append(NormalizedVulnerability(
                        cve_id=cve_id,
                        asset_ip=asset_name,
                        asset_hostname=asset_name,
                        severity=_cvss_to_severity(cvss_score),
                        cvss_score=cvss_score,
                        patch_available=patch_available,
                        source="blackduck",
                        source_confidence=0.8,
                        description=description,
                    ))

        return vulnerabilities


def _detect_blackduck_columns(headers, headers_lower):
    col_map = {}
    patterns = {
        "cve_id": ["cve", "vulnerability id", "vuln id", "cve id"],
        "cvss_score": ["cvss", "base score", "overall score", "cvss3"],
        "component": ["component", "package", "library", "artifact"],
        "version": ["version", "component version"],
        "description": ["description", "vulnerability name", "summary"],
        "remediation": ["remediation", "fix", "solution", "upgrade to"],
    }
    for field_name, field_patterns in patterns.items():
        for pattern in field_patterns:
            for i, h in enumerate(headers_lower):
                if pattern in h:
                    col_map[field_name] = headers[i]
                    break
            if field_name in col_map:
                break
    return col_map


def _cvss_to_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    return "Low"
