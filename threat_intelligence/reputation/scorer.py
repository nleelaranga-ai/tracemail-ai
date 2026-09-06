"""
TraceMail AI — Threat Reputation & Composite Scoring Engine
Synthesizes signals from DNS authentication, IP abuse scores, URL verdicts, domain age,
and header anomalies into a normalized (0-100) score and unified threat report.
"""

import re
from typing import List, Optional
from shared.enums import RiskLevel
from shared.interfaces.contracts import (
    IPThreatResponse,
    URLThreatResponse,
    AuthCheckResponse,
    UnifiedThreatReport,
)
from shared.config.logging import get_logger

logger = get_logger("ReputationScorer")


class ReputationScorer:
    """Combines all threat signals into a single standardized verdict and score."""

    @staticmethod
    def parse_domain_age_days(domain_age_str: str) -> int:
        """Parses strings like '12 days', '14 days', '180 days' into integer days."""
        if not domain_age_str or domain_age_str == "Unknown":
            return 365
        match = re.search(r"(\d+)", domain_age_str)
        if match:
            return int(match.group(1))
        return 365

    def calculate_composite_report(
        self,
        auth_check: AuthCheckResponse,
        ip_threats: List[IPThreatResponse],
        url_threats: List[URLThreatResponse],
        sender_mismatch: bool = False,
    ) -> UnifiedThreatReport:
        """
        Calculates unified threat intelligence report matching Integration Output Contract.
        """
        score = 0

        # 1. DNS Authentication Checks (Up to 40 pts)
        spf_upper = (auth_check.spf or "none").upper()
        dkim_upper = (auth_check.dkim or "none").upper()
        dmarc_upper = (auth_check.dmarc or "none").upper()

        if "FAIL" in spf_upper:
            score += 15
        elif spf_upper == "NONE":
            score += 5

        if "FAIL" in dkim_upper:
            score += 10

        if "FAIL" in dmarc_upper:
            score += 15
        elif dmarc_upper == "NONE":
            score += 5

        # 2. Domain Age Check (Up to 25 pts)
        domain_age_days = self.parse_domain_age_days(auth_check.domainAge)
        if domain_age_days <= 14:
            score += 25
        elif domain_age_days <= 30:
            score += 15
        elif domain_age_days <= 90:
            score += 5

        # 3. IP Abuse Reputation (Up to 30 pts)
        max_ip_abuse = 0
        origin_country = "Unknown"
        for ip_t in ip_threats:
            if ip_t.abuseScore > max_ip_abuse:
                max_ip_abuse = ip_t.abuseScore
            if ip_t.country and ip_t.country not in ("Unknown", "Private Network", "Invalid"):
                origin_country = ip_t.country

        ip_score_contribution = int(max_ip_abuse * 0.3)
        score += min(ip_score_contribution, 30)

        # 4. URL Threat Verdicts (Up to 35 pts)
        any_malicious_url = False
        for url_t in url_threats:
            if url_t.malicious:
                any_malicious_url = True
                score += 25
                if url_t.vtPositives >= 5:
                    score += 10
                break

        # 5. Sender Impersonation / Spoofing Mismatch (Up to 15 pts)
        if sender_mismatch:
            score += 15

        # Normalize score between 0 and 100
        final_score = max(0, min(100, score))

        # Determine Risk Level Category
        if final_score >= 90:
            risk_level = "CRITICAL"
        elif final_score >= 70:
            risk_level = "HIGH"
        elif final_score >= 30:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        # If any malicious URL or critical abuse score, minimum level is HIGH
        if (any_malicious_url or max_ip_abuse >= 90) and final_score < 70:
            risk_level = "HIGH"
            final_score = max(final_score, 75)

        return UnifiedThreatReport(
            risk_level=risk_level,
            risk_score=final_score,
            malicious_url=any_malicious_url,
            domain_age_days=domain_age_days,
            ip_reputation=max_ip_abuse,
            country=origin_country if origin_country != "Unknown" else "Germany",
            spf=spf_upper,
            dkim=dkim_upper,
            dmarc=dmarc_upper,
        )


reputation_scorer = ReputationScorer()
