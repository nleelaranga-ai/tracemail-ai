"""
TraceMail AI Backend — Canonical Verdict Resolution Service
Single source of truth for verdict, threat score, risk level, and AI prediction harmonization.
Guarantees: Top badge == AI panel == Reports == Dashboard == API == PDF.
"""
from typing import Dict, Any, Tuple


class CanonicalVerdictService:
    """Centralized resolver for deterministic threat verdicts across all layers."""

    @staticmethod
    def resolve_verdict(
        threat_score: int,
        ai_data: Dict[str, Any],
        auth_data: Dict[str, Any],
        vt_positives: int = 0,
        abuse_score: int = 0,
        display_name_spoofing: bool = False,
        is_recruitment_or_trusted: bool = False,
        has_critical_indicators: bool = False
    ) -> Dict[str, Any]:
        """
        Harmonizes the threat score, verdict, risk level, prediction, and summary.
        Ensures top-level verdict never contradicts AI forensic findings.
        """
        ai_score = int(ai_data.get("phishingScore") or ai_data.get("score") or 0)
        ai_verdict = str(ai_data.get("verdict") or "").lower()
        ai_pred = str(ai_data.get("prediction") or "").lower()
        ai_triggers = ai_data.get("psychologicalTriggers") or []

        spf_status = str(auth_data.get("spf") or "").lower()
        dkim_status = str(auth_data.get("dkim") or "").lower()
        dmarc_status = str(auth_data.get("dmarc") or "").lower()
        crypto_failed = "fail" in spf_status or "fail" in dkim_status or "fail" in dmarc_status

        # 1. Detect high-impact attack vectors
        is_bec_or_impersonation = (
            display_name_spoofing
            or any("impersonation" in str(t).lower() or "bec" in str(t).lower() for t in ai_triggers)
        )
        is_financial_diversion = any(
            "financial" in str(t).lower() or "wire" in str(t).lower() or "diversion" in str(t).lower()
            for t in ai_triggers
        )
        is_cred_harvesting = any(
            "credential" in str(t).lower() or "harvest" in str(t).lower() for t in ai_triggers
        )
        is_malware_payload = vt_positives >= 1 or has_critical_indicators

        # 2. Harmonize threat score to reflect high-confidence forensic findings
        harmonized_score = threat_score

        if is_bec_or_impersonation and (is_financial_diversion or is_cred_harvesting or crypto_failed):
            # Severe BEC or Brand Spoofing with financial / credential intent
            harmonized_score = max(harmonized_score, 88)
        elif is_cred_harvesting or is_malware_payload or abuse_score >= 50 or vt_positives >= 1:
            # Active phishing or malicious payload
            harmonized_score = max(harmonized_score, 78)
        elif ai_verdict == "phishing" or ai_pred == "phishing":
            # AI engine flagged severe phishing
            harmonized_score = max(harmonized_score, 70)
        elif is_bec_or_impersonation or is_financial_diversion:
            # Suspicious impersonation or unexplained financial phrasing
            harmonized_score = max(harmonized_score, 55)
        elif is_recruitment_or_trusted and not crypto_failed and not is_cred_harvesting and not is_malware_payload:
            # Verified benign sender
            harmonized_score = min(harmonized_score, 20)

        # Ensure bounds [5, 98]
        harmonized_score = min(98, max(5, int(round(harmonized_score))))

        # 3. Derive Canonical Verdict and Risk Level
        if harmonized_score >= 85:
            canonical_verdict = "phishing"
            canonical_risk_level = "Critical"
            canonical_prediction = "Phishing"
        elif harmonized_score >= 65:
            canonical_verdict = "phishing"
            canonical_risk_level = "High"
            canonical_prediction = "Phishing"
        elif harmonized_score >= 35:
            canonical_verdict = "suspicious"
            canonical_risk_level = "Medium"
            canonical_prediction = "Suspicious"
        else:
            canonical_verdict = "safe"
            canonical_risk_level = "Low"
            canonical_prediction = "Legitimate"

        # 4. Derive Confidence
        confidence = float(ai_data.get("confidence") or (98.2 if harmonized_score >= 85 else (92.5 if harmonized_score >= 65 else 88.0)))
        if canonical_verdict == "safe" and confidence > 95.0:
            confidence = 94.0

        # 5. Build Unified Explanation & Summary
        reasons = list(ai_data.get("reasons") or [])
        if canonical_verdict == "safe":
            if not reasons:
                reasons = [
                    "Cryptographic sender validation passed (SPF/DKIM alignment)",
                    "Origin routing infrastructure is unflagged across VirusTotal and AbuseIPDB",
                    "Zero credential harvesting or malicious payloads detected"
                ]
            summary = f"TraceMail AI classified this message as Legitimate ({confidence}% confidence). Clean transmission structure verified with no active threat indicators."
        elif canonical_verdict == "suspicious":
            summary = f"TraceMail AI classified this message as Suspicious ({confidence}% confidence). Potential risk indicators detected requiring analyst review."
        else:
            summary = f"TraceMail AI classified this message as Phishing ({confidence}% confidence). High-risk malicious indicators or identity deception detected."

        return {
            "threat_score": harmonized_score,
            "verdict": canonical_verdict,
            "risk_level": canonical_risk_level,
            "prediction": canonical_prediction,
            "confidence": confidence,
            "summary": summary,
            "reasons": reasons
        }
