#!/usr/bin/env python3

import csv
import xml.etree.ElementTree as ET
from typing import Any, List

from connectors.base import NormalizedVulnerability, ScannerConnector


class OpenVASConnector(ScannerConnector):
    def supported_formats(self) -> List[str]:
        return ["csv", "xml"]

    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        """Parse OpenVAS export (CSV or XML). data is a filepath string."""
        if str(data).lower().endswith(".xml"):
            return self._parse_xml(data)
        return self._parse_csv(data)

    def _parse_csv(self, filepath: str) -> List[NormalizedVulnerability]:
        vulnerabilities = []

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            headers_lower = [h.lower().strip() for h in headers]

            col_map = _detect_openvas_columns(headers, headers_lower)
            if "cve_id" not in col_map:
                return []

            for row in reader:
                cve_raw = row.get(col_map["cve_id"], "").strip()
                cve_ids = [c.strip() for c in cve_raw.replace(";", ",").split(",") if c.strip().startswith("CVE-")]
                if not cve_ids:
                    continue

                host = row.get(col_map.get("asset", ""), "").strip() or "Unknown"
                cvss_score = 5.0
                if "cvss_score" in col_map:
                    try:
                        cvss_score = float(row.get(col_map["cvss_score"], "0").strip())
                    except (ValueError, TypeError):
                        pass

                description = row.get(col_map.get("description", ""), "").strip()[:200]
                severity = _cvss_to_severity(cvss_score)

                for cve_id in cve_ids:
                    vulnerabilities.append(NormalizedVulnerability(
                        cve_id=cve_id,
                        asset_ip=host,
                        asset_hostname=host,
                        severity=severity,
                        cvss_score=cvss_score,
                        source="openvas",
                        source_confidence=0.8,
                        description=description,
                    ))

        return vulnerabilities

    def _parse_xml(self, filepath: str) -> List[NormalizedVulnerability]:
        vulnerabilities = []
        tree = ET.parse(filepath)
        root = tree.getroot()

        for result in root.iter("result"):
            host_elem = result.find("host")
            host = host_elem.text if host_elem is not None else ""

            nvt = result.find("nvt")
            if nvt is None:
                continue

            cve_elem = nvt.find("cve")
            cve_text = cve_elem.text if cve_elem is not None else ""
            if not cve_text or cve_text == "NOCVE":
                continue

            cve_ids = [c.strip() for c in cve_text.split(",") if c.strip().startswith("CVE-")]
            if not cve_ids:
                continue

            cvss_elem = nvt.find("cvss_base")
            cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else 5.0

            name_elem = nvt.find("name")
            description = name_elem.text[:200] if name_elem is not None and name_elem.text else ""

            for cve_id in cve_ids:
                vulnerabilities.append(NormalizedVulnerability(
                    cve_id=cve_id,
                    asset_ip=host,
                    asset_hostname=host,
                    severity=_cvss_to_severity(cvss_score),
                    cvss_score=cvss_score,
                    source="openvas",
                    source_confidence=0.8,
                    description=description,
                ))

        return vulnerabilities


def _detect_openvas_columns(headers, headers_lower):
    col_map = {}
    patterns = {
        "cve_id": ["cve", "cves", "nvt oid"],
        "cvss_score": ["cvss", "cvss_base", "severity"],
        "asset": ["host", "ip", "hostname", "target"],
        "description": ["name", "nvt name", "summary", "description"],
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
