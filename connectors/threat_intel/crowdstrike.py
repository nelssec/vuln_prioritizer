#!/usr/bin/env python3

import logging
from typing import List, Optional

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)


class NotConfiguredError(Exception):
    pass


class CrowdStrikeProvider(ThreatIntelProvider):
    """CrowdStrike Falcon threat intel stub (OAuth2 client credentials).

    Requires crowdstrike_client_id and crowdstrike_client_secret in config.
    """

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret

    def provider_name(self) -> str:
        return "CrowdStrike"

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        if not self.is_configured():
            logger.warning("CrowdStrike: credentials not configured, skipping enrichment")
            return vulns
        raise NotConfiguredError(
            "CrowdStrike integration requires a commercial license. "
            "Set crowdstrike_client_id and crowdstrike_client_secret in config."
        )
