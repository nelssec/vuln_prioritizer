#!/usr/bin/env python3

import logging
import time
from typing import Dict, List, Optional

import requests

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)

DEFAULT_EPSS_API = "https://api.first.org/data/v1/epss"
DEFAULT_BATCH_SIZE = 50
DEFAULT_RATE_LIMIT_DELAY = 1.0


class EPSSProvider(ThreatIntelProvider):
    def __init__(self, api_url: str = DEFAULT_EPSS_API, cache_db=None,
                 cache_max_age_days: int = 7, timeout: int = 10,
                 rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY):
        self.api_url = api_url
        self.cache_db = cache_db
        self.cache_max_age_days = cache_max_age_days
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay

    def provider_name(self) -> str:
        return "EPSS"

    def is_configured(self) -> bool:
        return True  # No auth required

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        cve_ids = list({v.cve_id for v in vulns})
        if not cve_ids:
            return vulns

        epss_data = self._fetch_scores(cve_ids)

        for vuln in vulns:
            if vuln.cve_id in epss_data:
                vuln.epss_score = epss_data[vuln.cve_id]["epss"]

        return vulns

    def _fetch_scores(self, cve_ids: List[str]) -> Dict[str, Dict]:
        epss_data = {}
        uncached = []

        # Check cache first
        if self.cache_db:
            for cve in cve_ids:
                cached = self.cache_db.get_epss_score(cve, max_age_days=self.cache_max_age_days)
                if cached:
                    epss_data[cve] = {"epss": cached.get("score", cached.get("epss", 0.0)),
                                      "percentile": cached.get("percentile", 0.0)}
                else:
                    uncached.append(cve)
        else:
            uncached = list(cve_ids)

        if not uncached:
            return epss_data

        # Fetch from API in batches
        for i in range(0, len(uncached), DEFAULT_BATCH_SIZE):
            batch = uncached[i:i + DEFAULT_BATCH_SIZE]
            self._fetch_batch(batch, epss_data)
            if i + DEFAULT_BATCH_SIZE < len(uncached):
                time.sleep(self.rate_limit_delay)

        return epss_data

    def _fetch_batch(self, cve_batch: List[str], epss_data: Dict):
        try:
            response = requests.get(
                self.api_url,
                params={"cve": ",".join(cve_batch)},
                headers={"User-Agent": "VulnPrioritizer/2.0", "Accept": "application/json"},
                timeout=self.timeout,
            )
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    cve = item.get("cve", "")
                    if cve:
                        epss_data[cve] = {
                            "epss": float(item.get("epss", 0)),
                            "percentile": float(item.get("percentile", 0)),
                        }
                        if self.cache_db and hasattr(self.cache_db, "cache_epss_score"):
                            self.cache_db.cache_epss_score(
                                cve,
                                epss_data[cve]["epss"],
                                epss_data[cve]["percentile"],
                                data.get("model_version", ""),
                                data.get("score_date", ""),
                            )
            else:
                logger.warning("EPSS API returned status %d", response.status_code)
        except Exception as e:
            logger.warning("Error fetching EPSS batch: %s", e)
