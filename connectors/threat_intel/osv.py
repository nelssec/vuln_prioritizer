#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional

import requests

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)

OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
OSV_MAX_BATCH = 1000


class OSVProvider(ThreatIntelProvider):
    """OSV.dev provider for open-source vulnerability data.

    Supports npm, PyPI, Go, Maven ecosystems. Feeds into SCA/BlackDuck scoring.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def provider_name(self) -> str:
        return "OSV"

    def is_configured(self) -> bool:
        return True  # No auth required

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        cve_ids = list({v.cve_id for v in vulns})
        if not cve_ids:
            return vulns

        osv_data = self._query_batch(cve_ids)

        for vuln in vulns:
            if vuln.cve_id in osv_data:
                data = osv_data[vuln.cve_id]
                if data.get("references"):
                    vuln.references = list(set(vuln.references + data["references"]))
                if data.get("cwe_ids"):
                    vuln.cwe_ids = list(set(vuln.cwe_ids + data["cwe_ids"]))
                if data.get("description") and not vuln.description:
                    vuln.description = data["description"][:200]

        return vulns

    def _query_batch(self, cve_ids: List[str]) -> Dict[str, dict]:
        results = {}

        for i in range(0, len(cve_ids), OSV_MAX_BATCH):
            batch = cve_ids[i:i + OSV_MAX_BATCH]
            queries = [{"vulnerability": {"id": cve_id}} for cve_id in batch]

            try:
                response = requests.post(
                    OSV_BATCH_API,
                    json={"queries": queries},
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                if response.status_code != 200:
                    logger.warning("OSV API returned %d", response.status_code)
                    continue

                data = response.json()
                for idx, result in enumerate(data.get("results", [])):
                    vulns_list = result.get("vulns", [])
                    if not vulns_list:
                        continue

                    cve_id = batch[idx]
                    osv_vuln = vulns_list[0]

                    entry = {"references": [], "cwe_ids": [], "description": ""}

                    for ref in osv_vuln.get("references", [])[:5]:
                        url = ref.get("url", "")
                        if url:
                            entry["references"].append(url)

                    summary = osv_vuln.get("summary", "")
                    if summary:
                        entry["description"] = summary

                    for alias in osv_vuln.get("database_specific", {}).get("cwe_ids", []):
                        if alias.startswith("CWE-"):
                            entry["cwe_ids"].append(alias)

                    results[cve_id] = entry

            except Exception as e:
                logger.warning("Error querying OSV batch: %s", e)

        return results
