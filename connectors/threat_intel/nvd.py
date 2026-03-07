#!/usr/bin/env python3

import logging
import time
from typing import List, Optional

import requests

from cache.store import FeedCache
from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BATCH_SIZE = 20
NVD_RATE_LIMIT_REQUESTS = 5
NVD_RATE_LIMIT_WINDOW = 30  # seconds

NVD_CACHE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS nvd_cache (
        cve_id TEXT PRIMARY KEY,
        cvss_v4_score REAL,
        cwe_ids TEXT,
        references TEXT,
        description TEXT,
        cached_at TEXT
    )
"""


class NVDProvider(ThreatIntelProvider):
    def __init__(self, cache: Optional[FeedCache] = None, timeout: int = 10):
        self.cache = cache
        self.timeout = timeout
        self._request_times: List[float] = []

        if self.cache:
            self.cache.register_feed("nvd", ttl_days=7, schema_sql=NVD_CACHE_SCHEMA)

    def provider_name(self) -> str:
        return "NVD"

    def is_configured(self) -> bool:
        return True  # No auth required

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        cve_ids = list({v.cve_id for v in vulns})
        if not cve_ids:
            return vulns

        nvd_data = {}

        # Check cache
        for cve_id in list(cve_ids):
            cached = self._get_cached(cve_id)
            if cached:
                nvd_data[cve_id] = cached
                cve_ids.remove(cve_id)

        # Fetch uncached in batches
        for i in range(0, len(cve_ids), NVD_BATCH_SIZE):
            batch = cve_ids[i:i + NVD_BATCH_SIZE]
            for cve_id in batch:
                data = self._fetch_single(cve_id)
                if data:
                    nvd_data[cve_id] = data

        # Apply enrichment
        for vuln in vulns:
            if vuln.cve_id in nvd_data:
                data = nvd_data[vuln.cve_id]
                if data.get("cvss_v4_score"):
                    vuln.cvss_v4_score = data["cvss_v4_score"]
                if data.get("cwe_ids"):
                    vuln.cwe_ids = list(set(vuln.cwe_ids + data["cwe_ids"]))
                if data.get("references"):
                    vuln.references = list(set(vuln.references + data["references"]))
                if data.get("description") and not vuln.description:
                    vuln.description = data["description"]

        return vulns

    def _respect_rate_limit(self):
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < NVD_RATE_LIMIT_WINDOW]
        if len(self._request_times) >= NVD_RATE_LIMIT_REQUESTS:
            sleep_time = NVD_RATE_LIMIT_WINDOW - (now - self._request_times[0]) + 0.5
            if sleep_time > 0:
                time.sleep(sleep_time)
        self._request_times.append(time.time())

    def _fetch_single(self, cve_id: str) -> Optional[dict]:
        self._respect_rate_limit()
        try:
            response = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers={"User-Agent": "VulnPrioritizer/2.0"},
                timeout=self.timeout,
            )
            if response.status_code != 200:
                logger.warning("NVD API returned %d for %s", response.status_code, cve_id)
                return None

            result = response.json()
            vulns = result.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})
            data = self._parse_cve_data(cve_data)

            if self.cache:
                self._store_cached(cve_id, data)

            return data

        except Exception as e:
            logger.warning("Error fetching NVD data for %s: %s", cve_id, e)
            return None

    def _parse_cve_data(self, cve_data: dict) -> dict:
        data = {"cvss_v4_score": None, "cwe_ids": [], "references": [], "description": ""}

        # Extract CVSSv4
        metrics = cve_data.get("metrics", {})
        for v4 in metrics.get("cvssMetricV40", []) + metrics.get("cvssMetricV4", []):
            cvss_data = v4.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score:
                data["cvss_v4_score"] = float(score)
                break

        # Extract CWE IDs
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    data["cwe_ids"].append(value)

        # Extract references (first 10)
        for ref in cve_data.get("references", [])[:10]:
            url = ref.get("url", "")
            if url:
                data["references"].append(url)

        # Extract description
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                data["description"] = desc.get("value", "")[:200]
                break

        return data

    def _get_cached(self, cve_id: str) -> Optional[dict]:
        if not self.cache:
            return None
        row = self.cache.fetchone(
            "SELECT cvss_v4_score, cwe_ids, references, description, cached_at FROM nvd_cache WHERE cve_id = ?",
            (cve_id,),
        )
        if not row:
            return None
        if self.cache.is_expired(row["cached_at"], "nvd"):
            return None
        return {
            "cvss_v4_score": row["cvss_v4_score"],
            "cwe_ids": row["cwe_ids"].split(",") if row["cwe_ids"] else [],
            "references": row["references"].split("|") if row["references"] else [],
            "description": row["description"] or "",
        }

    def _store_cached(self, cve_id: str, data: dict):
        if not self.cache:
            return
        from datetime import datetime
        self.cache.execute(
            "INSERT OR REPLACE INTO nvd_cache (cve_id, cvss_v4_score, cwe_ids, references, description, cached_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                cve_id,
                data.get("cvss_v4_score"),
                ",".join(data.get("cwe_ids", [])),
                "|".join(data.get("references", [])),
                data.get("description", ""),
                datetime.now().isoformat(),
            ),
        )
        self.cache.commit()
