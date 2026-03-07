#!/usr/bin/env python3

import csv
from typing import Any, List

from connectors.base import NormalizedVulnerability, ScannerConnector


class Rapid7Connector(ScannerConnector):
    def supported_formats(self) -> List[str]:
        return ["csv", "xml"]

    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        """Parse Rapid7 InsightVM/Nexpose CSV export. data is a filepath string."""
        vulnerabilities = []

        with open(data, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            headers_lower = [h.lower().strip() for h in headers]

            col_map = _detect_rapid7_columns(headers, headers_lower)
            if "cve_id" not in col_map:
                return []

            for row in reader:
                cve_raw = row.get(col_map["cve_id"], "").strip()
                cve_ids = [c.strip() for c in cve_raw.replace(";", ",").split(",") if c.strip().startswith("CVE-")]
                if not cve_ids:
                    continue

                host = row.get(col_map.get("asset", ""), "").strip() or "Unknown"
                hostname = row.get(col_map.get("hostname", ""), "").strip() or host

                cvss_score = 5.0
                if "cvss_score" in col_map:
                    try:
                        cvss_score = float(row.get(col_map["cvss_score"], "0").strip())
                    except (ValueError, TypeError):
                        pass

                description = row.get(col_map.get("description", ""), "").strip()[:200]

                exploit_str = row.get(col_map.get("exploitable", ""), "").strip().lower()
                exploit_available = exploit_str in ("true", "yes", "1")

                for cve_id in cve_ids:
                    vulnerabilities.append(NormalizedVulnerability(
                        cve_id=cve_id,
                        asset_ip=host,
                        asset_hostname=hostname,
                        severity=_cvss_to_severity(cvss_score),
                        cvss_score=cvss_score,
                        exploit_available=exploit_available,
                        source="rapid7",
                        source_confidence=0.85,
                        description=description,
                    ))

        return vulnerabilities


def _detect_rapid7_columns(headers, headers_lower):
    col_map = {}
    patterns = {
        "cve_id": ["cve", "cve_id", "vulnerability id"],
        "cvss_score": ["cvss", "cvss score", "cvss_v3_score", "risk score"],
        "asset": ["asset ip", "ip address", "ip", "host"],
        "hostname": ["hostname", "asset name", "dns name"],
        "description": ["title", "vulnerability", "name", "description"],
        "exploitable": ["exploitable", "exploit", "has exploit"],
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
