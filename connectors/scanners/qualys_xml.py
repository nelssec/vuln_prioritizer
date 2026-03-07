#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from typing import Any, List

from connectors.base import NormalizedVulnerability, ScannerConnector


class QualysXMLConnector(ScannerConnector):
    def supported_formats(self) -> List[str]:
        return ["xml"]

    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        """Parse Qualys XML export. data is a filepath string."""
        vulnerabilities = []

        tree = ET.parse(data)
        root = tree.getroot()

        # Qualys XML can use ASSET_DATA_REPORT or HOST_LIST_VM_DETECTION_OUTPUT
        # Try HOST_LIST_VM_DETECTION_OUTPUT format first
        for host in root.iter("HOST"):
            ip_elem = host.find("IP")
            ip = ip_elem.text if ip_elem is not None else ""
            dns_elem = host.find("DNS")
            hostname = dns_elem.text if dns_elem is not None else ip

            for detection in host.iter("DETECTION"):
                qid_elem = detection.find("QID")
                qid = qid_elem.text if qid_elem is not None else ""

                severity_elem = detection.find("SEVERITY")
                severity_val = int(severity_elem.text) if severity_elem is not None and severity_elem.text else 0

                status_elem = detection.find("STATUS")
                status = status_elem.text if status_elem is not None else ""
                if status and status.upper() not in {"ACTIVE", "NEW", "REOPENED", "RE-OPENED"}:
                    continue

                results_elem = detection.find("RESULTS")
                results_text = results_elem.text if results_elem is not None else ""

                # Extract CVEs from results or QID lookup
                cve_ids = _extract_cves_from_text(results_text)

                severity_map = {1: "Low", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
                cvss_map = {1: 2.0, 2: 3.0, 3: 5.5, 4: 7.5, 5: 9.5}

                for cve_id in cve_ids:
                    vulnerabilities.append(NormalizedVulnerability(
                        cve_id=cve_id,
                        asset_ip=ip,
                        asset_hostname=hostname,
                        severity=severity_map.get(severity_val, "Medium"),
                        cvss_score=cvss_map.get(severity_val, 5.0),
                        source="qualys_xml",
                        source_confidence=0.85,
                        description=f"QID {qid}" if qid else "",
                    ))

        # Try VULN_LIST format (Qualys KnowledgeBase export)
        for vuln in root.iter("VULN"):
            qid_elem = vuln.find("QID")
            cvss_elem = vuln.find("CVSS_BASE")
            title_elem = vuln.find("TITLE")
            cve_list_elem = vuln.find("CVE_LIST")

            cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else 5.0

            cve_ids = []
            if cve_list_elem is not None:
                for cve_elem in cve_list_elem.iter("CVE"):
                    id_elem = cve_elem.find("ID")
                    if id_elem is not None and id_elem.text and id_elem.text.startswith("CVE-"):
                        cve_ids.append(id_elem.text)

            description = title_elem.text if title_elem is not None else ""

            for cve_id in cve_ids:
                vulnerabilities.append(NormalizedVulnerability(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=_cvss_to_severity(cvss_score),
                    source="qualys_xml",
                    source_confidence=0.85,
                    description=description[:200] if description else "",
                ))

        return vulnerabilities


def _extract_cves_from_text(text: str) -> List[str]:
    import re
    if not text:
        return []
    return re.findall(r"CVE-\d{4}-\d{4,}", text)


def _cvss_to_severity(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    return "Low"
