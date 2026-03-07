#!/usr/bin/env python3

import logging
from typing import List, Set

import requests

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVProvider(ThreatIntelProvider):
    def __init__(self, api_url: str = DEFAULT_KEV_URL, cache_db=None,
                 cache_max_age_days: int = 1, timeout: int = 10):
        self.api_url = api_url
        self.cache_db = cache_db
        self.cache_max_age_days = cache_max_age_days
        self.timeout = timeout
        self._kev_set: Set[str] = set()

    def provider_name(self) -> str:
        return "CISA_KEV"

    def is_configured(self) -> bool:
        return True  # No auth required

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        kev_set = self._fetch_kev()

        for vuln in vulns:
            if vuln.cve_id in kev_set:
                vuln.in_kev = True
                vuln.exploit_available = True

        return vulns

    def _fetch_kev(self) -> Set[str]:
        if self._kev_set:
            return self._kev_set

        # Check cache
        if self.cache_db:
            cached = self.cache_db.get_all_cisa_kev_cves(max_age_days=self.cache_max_age_days)
            if cached:
                self._kev_set = cached
                return self._kev_set

        # Fetch from API
        try:
            response = requests.get(
                self.api_url,
                headers={"User-Agent": "VulnPrioritizer/2.0"},
                timeout=self.timeout,
            )
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "")
                    if cve_id:
                        self._kev_set.add(cve_id)
                        if self.cache_db and hasattr(self.cache_db, "cache_cisa_kev"):
                            self.cache_db.cache_cisa_kev(
                                cve_id,
                                vuln.get("vendorProject", ""),
                                vuln.get("product", ""),
                                vuln.get("vulnerabilityName", ""),
                                vuln.get("dateAdded", ""),
                                vuln.get("shortDescription", ""),
                                vuln.get("requiredAction", ""),
                                vuln.get("dueDate", ""),
                            )
                logger.info("Loaded %d CVEs from CISA KEV", len(self._kev_set))
            else:
                logger.warning("Failed to fetch CISA KEV: %d", response.status_code)
        except Exception as e:
            logger.warning("Error fetching CISA KEV: %s", e)

        return self._kev_set
