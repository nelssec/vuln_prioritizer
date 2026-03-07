#!/usr/bin/env python3

import csv
from typing import Any, List

from connectors.base import NormalizedVulnerability, ScannerConnector


ACTIVE_STATUSES = {"ACTIVE", "REOPENED", "NEW", "OPEN", "RE-OPENED"}


class QualysCSVConnector(ScannerConnector):
    def supported_formats(self) -> List[str]:
        return ["csv"]

    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        """Parse Qualys CSV export. data is a filepath string."""
        vulnerabilities = []

        with open(data, "r", encoding="utf-8") as f:
            first_line = f.readline()
            if first_line.startswith('"Note:'):
                while True:
                    line = f.readline()
                    if not line or not line.startswith('"Note:'):
                        break
            else:
                f.seek(0)

            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            headers_lower = [h.lower().strip() for h in headers]

            # Build column mapping
            col_map = _detect_columns(headers, headers_lower)

            if "cve_id" not in col_map:
                return []

            for row in reader:
                cve_raw = row.get(col_map["cve_id"], "").strip()
                if not cve_raw or not cve_raw.startswith("CVE-"):
                    continue

                # Handle comma-separated CVEs
                cve_ids = [c.strip() for c in cve_raw.split(",") if c.strip().startswith("CVE-")]
                if not cve_ids:
                    continue

                # Check status if available
                if "status" in col_map:
                    status = row.get(col_map["status"], "").strip().upper()
                    if status and status not in ACTIVE_STATUSES:
                        continue

                asset_name = row.get(col_map.get("asset", ""), "Unknown").strip() or "Unknown"
                description = row.get(col_map.get("description", ""), "").strip()[:200]

                cvss_score = _extract_cvss(row, col_map, headers_lower)
                severity = _cvss_to_severity(cvss_score)

                for cve_id in cve_ids:
                    vulnerabilities.append(NormalizedVulnerability(
                        cve_id=cve_id,
                        asset_ip=asset_name,
                        asset_hostname=asset_name,
                        severity=severity,
                        cvss_score=cvss_score,
                        source="qualys_csv",
                        source_confidence=0.85,
                        description=description,
                    ))

        return vulnerabilities


def _detect_columns(headers, headers_lower):
    col_map = {}
    patterns = {
        "cve_id": ["cve", "cve_id", "cveid"],
        "cvss_score": ["cvss", "cvss score", "cvss_score", "cvssv3", "cvss v3", "base score"],
        "asset": ["host", "hostname", "asset", "ip", "target"],
        "description": ["description", "summary", "title", "name"],
        "severity": ["severity", "risk", "threat"],
        "status": ["status", "vuln status"],
        "criticality": ["criticality", "asset criticality"],
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


def _extract_cvss(row, col_map, headers_lower):
    if "cvss_score" in col_map:
        try:
            return float(row.get(col_map["cvss_score"], "0").strip())
        except (ValueError, TypeError):
            pass
    if "severity" in col_map:
        severity = row.get(col_map["severity"], "").strip().upper()
        severity_map = {"CRITICAL": 9.5, "HIGH": 7.5, "SEVERE": 7.5, "MEDIUM": 5.5, "MODERATE": 5.5, "LOW": 3.0}
        return severity_map.get(severity, 5.0)
    return 5.0


def _cvss_to_severity(cvss_score):
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"
