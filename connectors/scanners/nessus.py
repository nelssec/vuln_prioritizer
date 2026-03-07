#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from typing import Any, List

from connectors.base import NormalizedVulnerability, ScannerConnector


class NessusConnector(ScannerConnector):
    def supported_formats(self) -> List[str]:
        return ["nessus", "xml"]

    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        """Parse Nessus/Tenable .nessus XML file. data is a filepath string."""
        vulnerabilities = []

        tree = ET.parse(data)
        root = tree.getroot()

        for host in root.findall(".//ReportHost"):
            hostname = host.get("name", "")

            # Try to extract IP from host properties
            ip = hostname
            for tag in host.findall(".//HostProperties/tag"):
                if tag.get("name") == "host-ip":
                    ip = tag.text or hostname
                    break

            for item in host.findall(".//ReportItem"):
                severity = int(item.get("severity", 0))
                if severity == 0:
                    continue

                cves = [cve.text for cve in item.findall(".//cve") if cve.text]
                if not cves:
                    continue

                cvss_score = 0.0
                cvss_elem = item.find(".//cvss3_base_score")
                if cvss_elem is not None and cvss_elem.text:
                    try:
                        cvss_score = float(cvss_elem.text)
                    except ValueError:
                        pass

                if cvss_score == 0.0:
                    cvss_elem = item.find(".//cvss_base_score")
                    if cvss_elem is not None and cvss_elem.text:
                        try:
                            cvss_score = float(cvss_elem.text)
                        except ValueError:
                            pass

                description_elem = item.find(".//description")
                description = (description_elem.text or "")[:200] if description_elem is not None else ""

                exploit_elem = item.find(".//exploit_available")
                exploit_available = exploit_elem is not None and exploit_elem.text == "true"

                patch_elem = item.find(".//patch_publication_date")
                patch_available = patch_elem is not None and bool(patch_elem.text)

                severity_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

                for cve_id in cves:
                    vulnerabilities.append(NormalizedVulnerability(
                        cve_id=cve_id,
                        asset_ip=ip,
                        asset_hostname=hostname,
                        severity=severity_map.get(severity, "Medium"),
                        cvss_score=cvss_score,
                        exploit_available=exploit_available,
                        patch_available=patch_available,
                        source="nessus",
                        source_confidence=0.9,
                        description=description,
                    ))

        return vulnerabilities
