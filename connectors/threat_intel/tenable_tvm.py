#!/usr/bin/env python3

import logging
from typing import List, Optional

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)


class NotConfiguredError(Exception):
    pass


class TenableTVMProvider(ThreatIntelProvider):
    """Tenable Vulnerability Management API stub.

    Requires tenable_access_key and tenable_secret_key in config.
    """

    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None):
        self.access_key = access_key
        self.secret_key = secret_key

    def provider_name(self) -> str:
        return "TenableTVM"

    def is_configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        if not self.is_configured():
            logger.warning("Tenable TVM: credentials not configured, skipping enrichment")
            return vulns
        raise NotConfiguredError(
            "Tenable TVM integration requires API credentials. "
            "Set tenable_access_key and tenable_secret_key in config."
        )
