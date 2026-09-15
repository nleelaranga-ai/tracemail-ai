import hashlib
import socket
from backend.database.connection import Session
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from backend.models.scan import (
    Investigation,
    EmailRecord,
    ScanRecord,
    AIResultRecord,
    HeaderRecord,
    IOCEntityRecord
)
from backend.models.threat import ThreatResult
from backend.parsers.email_parser import EmailParser
from backend.parsers.ioc_parser import IOCParser
from backend.services.scan_service import ScanService
from backend.services.verdict_service import CanonicalVerdictService
from backend.services.threat_intelligence import ThreatIntelligenceGateway
from backend.services.notification_service import NotificationService
from backend.utils.logger import logger


class EmailService:
    @classmethod
    async def process_eml_file(
        cls,
        db: Session,
        content_bytes: bytes,
        filename: str = "email.eml",
        owner_user_id: Optional[str] = None
    ) -> Investigation:
        """
        Parses email, orchestrates threat and AI analysis, computes weighted threat score,
        and saves to database matching the unified master architecture.
        """
        if isinstance(content_bytes, str):
            content_bytes = content_bytes.encode("utf-8", errors="replace")
        elif not isinstance(content_bytes, (bytes, bytearray)):
            content_bytes = bytes(content_bytes or b"")

        evidence_hash = hashlib.sha256(content_bytes).hexdigest()
        parsed = EmailParser.parse_eml_bytes(content_bytes)
        
        sender = parsed.get("sender") or "unknown@sender.net"
        recipient = parsed.get("recipient") or "analyst@target.local"
        subject = parsed.get("subject") or "No Subject"
        domain = parsed.get("domain") or (sender.split("@")[-1].strip().strip(">") if "@" in sender else "unknown.net")
        body_text = parsed.get("body_text") or ""
        body_html = parsed.get("body_html") or ""
        raw_headers = parsed.get("raw_headers") or ""
        reply_to = parsed.get("reply_to") or ""
        message_id = parsed.get("message_id") or ""
        attachments = parsed.get("attachments") or []
        iocs = parsed.get("iocs") or {}

        recipient = parsed.get("recipient") or "analyst@target.local"
        recipient_domain = ""
        if "@" in recipient:
            recipient_domain = recipient.split("@")[-1].strip().strip(">").strip(";").strip(")").lower()

        extracted_ips = list(dict.fromkeys(iocs.get("ips", [])))
        extracted_urls = list(dict.fromkeys(iocs.get("urls", [])))
        extracted_domains = [
            d for d in list(dict.fromkeys(iocs.get("domains", [])))
            if not IOCParser.is_allowlisted_domain(d, recipient_domain)
        ]
        if domain and not IOCParser.is_allowlisted_domain(domain, recipient_domain) and domain not in extracted_domains:
            extracted_domains.append(domain)

        # 1. Determine origin IP and enrich all IP hops
        origin_ip = parsed.get("origin_ip")
        if not origin_ip and extracted_ips:
            origin_ip = extracted_ips[0]
        if not origin_ip and domain and domain != "unknown.net":
            try:
                resolved_ip = socket.gethostbyname(domain)
                if not (resolved_ip.startswith("10.") or resolved_ip.startswith("127.") or resolved_ip.startswith("192.168.")):
                    origin_ip = resolved_ip
            except Exception:
                pass
        if not origin_ip:
            origin_ip = "127.0.0.1"
        
        threat_items = []
        hop_objects = []

        for ip in extracted_ips:
            threat = await ScanService.query_ip_threat(ip)
            threat_items.append({
                "type": "ip",
                "value": ip,
                "reputation": threat.get("abuseScore", 0),
                "geo": f"{threat.get('city', 'Unknown')}, {threat.get('country', 'Unknown')}",
                "malicious": threat.get("malicious", False)
            })
            hop_objects.append(threat)

        # Ensure origin IP is included in hops
        origin_threat = await ScanService.query_ip_threat(origin_ip)
        if not any(h.get("ip") == origin_ip for h in hop_objects):
            hop_objects.insert(0, origin_threat)
            threat_items.insert(0, {
                "type": "ip",
                "value": origin_ip,
                "reputation": origin_threat.get("abuseScore", 0),
                "geo": f"{origin_threat.get('city', 'Unknown')}, {origin_threat.get('country', 'Unknown')}",
                "malicious": origin_threat.get("malicious", False)
            })

        # Process URLs with VirusTotal
        vt_primary = None
        for url in extracted_urls:
            threat = await ScanService.query_url_threat(url)
            threat_items.append({
                "type": "url",
                "value": url,
                "reputation": 95 if threat.get("malicious") else 0,
                "geo": "Global CDN",
                "malicious": threat.get("malicious", False)
            })
            if not vt_primary:
                vt_primary = threat

        first_url = extracted_urls[0] if extracted_urls else (f"http://{domain}" if domain else "")
        if not vt_primary and first_url:
            vt_primary = await ScanService.query_url_threat(first_url)

        # 2. Query WHOIS & RDAP for Domain
        whois_data = await ScanService.query_whois(domain)

        # 3. Query Unified Threat Intelligence Gateway across all 7 providers
        threat_report = await ThreatIntelligenceGateway.enrich_threat_intel(
            ip=origin_threat.get("ip", origin_ip),
            domain=domain,
            urls=extracted_urls,
            raw_headers=raw_headers,
            attachments=attachments
        )
        urlscan_data = threat_report.urlscan.dict()

        # 4. Query Auth Alignment (SPF, DKIM, DMARC)
        auth_data = await ScanService.query_auth_check(raw_headers)

        # 5. Query AI Engine with Identity Spoofing & BEC context and cryptographic alignment
        ai_data = await ScanService.query_ai_engine(
            email_body=body_text,
            headers=raw_headers,
            extracted_urls=extracted_urls,
            extracted_ips=extracted_ips,
            sender=sender,
            display_name=parsed.get("display_name"),
            display_name_spoofing=parsed.get("display_name_spoofing", False),
            impersonated_brand=parsed.get("impersonated_brand"),
            reply_to_mismatch=parsed.get("reply_to_mismatch", False),
            return_path_mismatch=parsed.get("return_path_mismatch", False),
            auth_data=auth_data
        )

        # 6. Calculate Dynamic Weighted Threat Score (Section 2.E)
        vt_pos = vt_primary.get("vtPositives", 0) if vt_primary else 0
        vt_tot = vt_primary.get("vtTotal", 90) if vt_primary else 90
        abuse_sc = origin_threat.get("abuseScore", 0)
        dom_age = whois_data.get("domain_age_days", 180)
        ai_conf = ai_data.get("confidence", 80.0)
        is_phish = ai_data.get("verdict") == "phishing" or ai_data.get("prediction") == "Phishing"

        scoring_result = ScanService.calculate_weighted_threat_score(
            vt_positives=vt_pos,
            vt_total=vt_tot,
            spf=auth_data.get("spf", "none"),
            dkim=auth_data.get("dkim", "none"),
            abuse_score=abuse_sc,
            domain_age_days=dom_age,
            ai_confidence=ai_conf,
            is_phishing=is_phish,
            ai_phishing_score=ai_data.get("phishingScore")
        )

        verdict_res = CanonicalVerdictService.resolve_verdict(
            threat_score=scoring_result["threat_score"],
            ai_data=ai_data,
            auth_data=auth_data,
            vt_positives=vt_pos,
            abuse_score=abuse_sc,
            display_name_spoofing=parsed.get("display_name_spoofing", False),
            is_recruitment_or_trusted=any(t in (domain or "").lower() for t in ["internshala.com", "google.com", "github.com", "sbi.co.in", "amazon.in"]),
            has_critical_indicators=any(item.get("malicious") for item in threat_items)
        )

        final_threat_score = verdict_res["threat_score"]
        final_risk_level = verdict_res["risk_level"]
        final_verdict = verdict_res["verdict"]

        # 7. Generate Investigation Timeline & IOC Chips
        now_dt = datetime.now(timezone.utc)
        timeline_steps = ScanService.generate_investigation_timeline(now_dt)
        ioc_chips = ScanService.generate_ioc_chips(
            urls=extracted_urls,
            ips=extracted_ips,
            domains=extracted_domains,
            attachments=attachments,
            threat_results=threat_items
        )

        # 8. Generate GeoJSON, Hop Timeline, Attack Graph, and Action Items
        try:
            origin_lat = float(origin_threat.get("lat") or 0.0)
        except (ValueError, TypeError):
            origin_lat = 0.0
        try:
            origin_lon = float(origin_threat.get("lon") or 0.0)
        except (ValueError, TypeError):
            origin_lon = 0.0

        geojson = ScanService.generate_geojson(
            hop_objects,
            origin_city=origin_threat.get("city", "Origin Node"),
            origin_lat=origin_lat,
            origin_lon=origin_lon
        )
        hop_timeline = ScanService.generate_timeline(hop_objects, default_ip=origin_ip)
        attack_graph = ScanService.generate_attack_graph(sender, recipient, hop_objects, is_phishing=(final_verdict == "phishing"))
        action_items = ScanService.generate_action_items(
            threat_score=final_threat_score,
            risk_level=final_risk_level,
            domain=domain,
            origin_ip=origin_ip,
            is_phishing=(final_verdict == "phishing"),
            display_name_spoofing=parsed.get("display_name_spoofing", False)
        )

        # Assemble summary structures
        vt_summary = {
            "malicious_vendors": vt_pos,
            "total_vendors": vt_tot,
            "scan_date": vt_primary.get("scanDate") if vt_primary else now_dt.isoformat(),
            "positives": vt_pos
        }
        real_abuse_reports = origin_threat.get("totalReports") or origin_threat.get("total_reports")
        if real_abuse_reports is None:
            real_abuse_reports = 0

        abuse_summary = {
            "confidence_score": abuse_sc,
            "isp": origin_threat.get("isp", "Internet Relay Node"),
            "total_reports": real_abuse_reports,
            "is_malicious": origin_threat.get("malicious", False)
        }
        dns_summary = {
            "spf": auth_data.get("spf", "none"),
            "dkim": auth_data.get("dkim", "none"),
            "dmarc": auth_data.get("dmarc", "none")
        }
        ai_summary_obj = {
            "prediction": verdict_res["prediction"],
            "verdict": verdict_res["verdict"],
            "confidence": verdict_res["confidence"],
            "summary": verdict_res["summary"],
            "reasons": verdict_res["reasons"]
        }

        try:
            # 9. Persist Investigation record
            investigation = Investigation(
                status="complete",
                sender=str(sender or "")[:255],
                recipient=str(recipient or "")[:255],
                subject=str(subject or "No Subject")[:500],
                domain=str(domain or "unknown")[:255],
                ip=str(origin_threat.get("ip") or origin_ip or "")[:64],
                country=str(origin_threat.get("country") or "Unknown")[:100],
                city=str(origin_threat.get("city") or "Unknown")[:100],
                latitude=origin_threat.get("lat", 0.0),
                longitude=origin_threat.get("lon", 0.0),
                phishing_score=final_threat_score,
                verdict=str(final_verdict or "suspicious")[:50],
                risk_level=str(final_risk_level or "Medium")[:50],
                explanation=ai_data.get("explanation", ""),
                ai_summary=ai_summary_obj["summary"],
                raw_headers=raw_headers,
                body_text=body_text,
                entities=ai_data.get("entities", {}),
                auth_results=auth_data,
                hop_timeline=hop_timeline,
                timeline=timeline_steps,
                geojson_map=geojson,
                attack_graph=attack_graph,
                threat_results=threat_items,
                virus_total=threat_report.virus_total.model_dump(),
                abuse_ipdb=threat_report.ip.model_dump(),
                whois=threat_report.domain.model_dump(),
                dns=threat_report.authentication.model_dump(),
                urlscan=threat_report.urlscan.model_dump(),
                google_safe_browsing=threat_report.google_safe_browsing.model_dump(),
                ai_analysis=ai_summary_obj,
                ioc=ioc_chips,
                evidence_hash=str(evidence_hash or "")[:64],
                action_items=action_items,
                owner_user_id=str(owner_user_id)[:64] if owner_user_id else None
            )
            db.add(investigation)
            db.commit()
            db.refresh(investigation)

            # 10. Persist Relational Tables (scans, emails, ai_results)
            scan_rec = ScanRecord(
                scan_id=investigation.id,
                sender=str(sender or "")[:255],
                domain=str(domain or "")[:255],
                ip=str(investigation.ip or "")[:64],
                country=str(investigation.country or "")[:100],
                city=str(investigation.city or "")[:100],
                latitude=investigation.latitude,
                longitude=investigation.longitude,
                threat_score=final_threat_score,
                risk_level=str(final_risk_level or "Low")[:50],
                status="complete"
            )
            db.add(scan_rec)

            email_rec = EmailRecord(
                scan_id=investigation.id,
                sender=str(sender or "")[:255],
                recipient=str(recipient or "")[:255],
                subject=str(subject or "")[:500],
                message_id=str(message_id or "")[:255],
                reply_to=str(reply_to or "")[:255],
                raw_eml=raw_headers + "\n\n" + body_text,
                body_plain=body_text,
                body_html=body_html,
                date_sent=now_dt
            )
            db.add(email_rec)

            ai_rec = AIResultRecord(
                scan_id=investigation.id,
                prediction=str(ai_summary_obj.get("prediction", "Suspicious"))[:50],
                confidence=ai_summary_obj.get("confidence", 0.0),
                summary=ai_summary_obj.get("summary", ""),
                reasons_json=ai_summary_obj.get("reasons", [])
            )
            db.add(ai_rec)

            # 11. Save individual threat indicators
            for item in threat_items:
                tr = ThreatResult(
                    investigation_id=investigation.id,
                    indicator_type=str(item.get("type", "unknown"))[:32],
                    indicator_value=str(item.get("value", ""))[:500],
                    reputation_score=int(item.get("reputation", 0) or 0),
                    is_malicious=bool(item.get("malicious", False)),
                    geo_location=str(item.get("geo", "") or "")[:255]
                )
                db.add(tr)

            # 12. Save Parsed Headers to headers table
            if raw_headers:
                for line in raw_headers.splitlines():
                    if ":" in line and not line.startswith(" ") and not line.startswith("\t"):
                        h_name, _, h_val = line.partition(":")
                        h_name = h_name.strip()
                        h_val = h_val.strip()
                        if h_name:
                            db.add(HeaderRecord(
                                scan_id=investigation.id,
                                header_name=h_name[:255],
                                header_value=h_val
                            ))

            # 13. Save Extracted IOCs to ioc_entities table
            for chip in ioc_chips:
                c_type = chip.get("type", "generic")
                c_val = str(chip.get("value", ""))
                c_mal = chip.get("malicious", False)
                if c_val:
                    db.add(IOCEntityRecord(
                        scan_id=investigation.id,
                        ioc_type=str(c_type)[:32],
                        ioc_value=c_val[:500],
                        threat_score=final_threat_score if c_mal else 0,
                        is_malicious=bool(c_mal)
                    ))
            db.commit()
        except Exception as db_err:
            db.rollback()
            logger.exception(f"Database error while saving investigation: {db_err}")
            raise

        # Send alert if high severity
        if final_threat_score >= 65:
            NotificationService.send_threat_alert(
                investigation_id=investigation.id,
                verdict=investigation.verdict,
                score=investigation.phishing_score,
                recipient=recipient
            )

        logger.info(f"Successfully processed email investigation: {investigation.id}, ThreatScore={final_threat_score}, RiskLevel={final_risk_level}, City={investigation.city}, Country={investigation.country}")
        return investigation

