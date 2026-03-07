#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple

from connectors.base import NormalizedVulnerability

SCORING_PROFILES: Dict[str, Dict[str, float]] = {
    "default": {
        "cvss": 0.30,
        "epss": 0.25,
        "kev": 0.20,
        "exploit": 0.25,
    },
    "cloud_workload": {
        "cvss": 0.25,
        "epss": 0.30,
        "kev": 0.20,
        "exploit": 0.25,
    },
    "onprem_server": {
        "cvss": 0.30,
        "epss": 0.25,
        "kev": 0.20,
        "exploit": 0.25,
    },
    "oss_library": {
        "cvss": 0.20,
        "epss": 0.20,
        "kev": 0.15,
        "exploit": 0.20,
        "patch_available": 0.25,
    },
}


class VulnerabilityScorer:
    def __init__(self, profiles: Optional[Dict[str, Dict[str, float]]] = None):
        self.profiles = profiles or SCORING_PROFILES

    def score(self, vuln: NormalizedVulnerability, profile: str = "default") -> float:
        weights = self.profiles.get(profile, self.profiles["default"])

        # Normalize CVSS to 0-100
        cvss_component = (vuln.cvss_score / 10.0) * 100.0

        # EPSS to 0-100
        epss_component = (vuln.epss_score or 0.0) * 100.0

        # KEV: boolean -> 0 or 100
        kev_component = 100.0 if vuln.in_kev else 0.0

        # Exploit available: boolean -> 0 or 100
        exploit_component = 100.0 if vuln.exploit_available else 0.0

        score = (
            cvss_component * weights.get("cvss", 0) +
            epss_component * weights.get("epss", 0) +
            kev_component * weights.get("kev", 0) +
            exploit_component * weights.get("exploit", 0)
        )

        # patch_available factor (for oss_library profile)
        if "patch_available" in weights:
            patch_component = 100.0 if vuln.patch_available else 0.0
            score += patch_component * weights["patch_available"]

        return round(min(score, 100.0), 2)

    def score_all(self, vulns: List[NormalizedVulnerability],
                  profile: str = "default") -> List[Tuple[NormalizedVulnerability, float]]:
        results = [(vuln, self.score(vuln, profile)) for vuln in vulns]
        results.sort(key=lambda x: x[1], reverse=True)
        return results
