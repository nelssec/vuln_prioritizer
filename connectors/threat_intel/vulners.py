#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional

import requests

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)

VULNERS_API_URL = "https://vulners.com/api/v3/search/id/"


class VulnersProvider(ThreatIntelProvider):
    """Vulners API for exploit availability, PoC status, Metasploit module flags.

    API key is optional; degrades gracefully if not set.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout

    def provider_name(self) -> str:
        return "Vulners"

    def is_configured(self) -> bool:
        return True  # Works without key (with rate limits)

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        cve_ids = list({v.cve_id for v in vulns})
        if not cve_ids:
            return vulns

        vulners_data = self._fetch_exploit_info(cve_ids)

        for vuln in vulns:
            if vuln.cve_id in vulners_data:
                data = vulners_data[vuln.cve_id]
                if data.get("exploit_available"):
                    vuln.exploit_available = True
                if data.get("references"):
                    vuln.references = list(set(vuln.references + data["references"]))

        return vulns

    def _fetch_exploit_info(self, cve_ids: List[str]) -> Dict[str, dict]:
        results = {}

        # Process in batches of 20
        for i in range(0, len(cve_ids), 20):
            batch = cve_ids[i:i + 20]
            try:
                payload = {"id": batch}
                if self.api_key:
                    payload["apiKey"] = self.api_key

                response = requests.post(
                    VULNERS_API_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                if response.status_code != 200:
                    logger.warning("Vulners API returned %d", response.status_code)
                    continue

                data = response.json()
                if data.get("result") != "OK":
                    continue

                for cve_id, entries in data.get("data", {}).get("documents", {}).items():
                    if not isinstance(entries, dict):
                        continue

                    entry = {"exploit_available": False, "references": []}

                    # Check for exploit/metasploit type entries
                    bulletin_type = entries.get("type", "")
                    if bulletin_type in ("exploit", "metasploit", "packetstorm", "seebug"):
                        entry["exploit_available"] = True

                    href = entries.get("href", "")
                    if href:
                        entry["references"].append(href)

                    results[cve_id] = entry

            except Exception as e:
                logger.warning("Error fetching Vulners data: %s", e)

        return results
