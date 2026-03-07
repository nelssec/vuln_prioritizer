#!/usr/bin/env python3

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedVulnerability:
    cve_id: str
    asset_ip: str = ""
    asset_hostname: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cvss_v4_score: Optional[float] = None
    epss_score: Optional[float] = None
    in_kev: bool = False
    exploit_available: bool = False
    patch_available: Optional[bool] = None
    source: str = ""
    source_confidence: float = 1.0
    cloud_metadata: Dict[str, Any] = field(default_factory=dict)
    threat_actor_campaigns: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    description: str = ""
    references: List[str] = field(default_factory=list)


class ScannerConnector(ABC):
    @abstractmethod
    def parse(self, data: Any) -> List[NormalizedVulnerability]:
        ...

    @abstractmethod
    def supported_formats(self) -> List[str]:
        ...


class ThreatIntelProvider(ABC):
    @abstractmethod
    def enrich(self, vulns: List[NormalizedVulnerability]) -> List[NormalizedVulnerability]:
        ...

    @abstractmethod
    def provider_name(self) -> str:
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        ...
