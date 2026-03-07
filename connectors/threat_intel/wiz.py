#!/usr/bin/env python3

import logging
from typing import List, Optional

from connectors.base import NormalizedVulnerability, ThreatIntelProvider

logger = logging.getLogger(__name__)


class NotConfiguredError(Exception):
    pass


class WizProvider(ThreatIntelProvider):
    """Wiz cloud security platform API stub.

    Requires wiz_client_id and wiz_client_secret in config.
    """

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret

    def provider_name(self) -> str:
        return "Wiz"

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        if not self.is_configured():
            logger.warning("Wiz: credentials not configured, skipping enrichment")
            return vulns
        raise NotConfiguredError(
            "Wiz integration requires API credentials. "
            "Set wiz_client_id and wiz_client_secret in config."
        )
