"""
TraceMail AI Backend — Database Seeder
"""
from datetime import datetime, timezone
from backend.database.connection import SessionLocal, init_db
from backend.models.user import User
from backend.models.scan import Investigation
from backend.services.auth_service import AuthService
from backend.utils.logger import logger


def seed_database():
    init_db()
    db = SessionLocal()
    try:
        # 1. Seed Demo Analyst User
        analyst_email = "analyst@tracemail.ai"
        existing_user = db.query(User).filter(User.email == analyst_email).first()
        if not existing_user:
            AuthService.register_user(
                db=db,
                email=analyst_email,
                password="Password123!",
                name="Chief SOC Analyst"
            )
            logger.info(f"Seeded demo user: {analyst_email} (Password123!)")

        # 2. Seed Master Investigation Cases
        # Case A: PayPal Credential Phish
        inv_id_1 = "inv_paypal_phish_demo_01"
        if not db.query(Investigation).filter(Investigation.id == inv_id_1).first():
            demo_inv_1 = Investigation(
                id=inv_id_1,
                status="complete",
                sender="support@paypal-security-update.com",
                recipient="victim@corporate-domain.com",
                subject="URGENT: Unauthorized access detected - Verify Identity",
                received_at=datetime.now(timezone.utc),
                domain="paypal-security-update.com",
                ip="185.220.101.4",
                city="Frankfurt",
                country="Germany",
                phishing_score=94,
                verdict="phishing",
                risk_level="Critical",
                explanation="Critical credential harvesting campaign. Deceptive lookalike domain 'paypa1-secure.com' detected, failing SPF/DMARC authentication.",
                evidence_hash="d2c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
                action_items=[
                    "Block domain paypa1-secure.com on email gateway and perimeter DNS.",
                    "Add IP 185.220.101.4 to firewall deny lists.",
                    "Revoke active SSO sessions for recipient.",
                    "Search SIEM for any user clicks to paypa1-secure.com."
                ],
                raw_headers="Received: from mail.sketchy-relay.net (185.220.101.4)\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail",
                body_text="Dear Customer, your account has been restricted due to suspicious logins. Please verify at http://paypa1-secure.com/login immediately.",
                entities={
                    "urls": ["http://paypa1-secure.com/login"],
                    "ips": ["185.220.101.4"],
                    "domains": ["paypa1-secure.com"],
                    "senderClaim": "PayPal Security <support@paypal.com>",
                    "senderActual": "attacker@sketchy-relay.net"
                },
                auth_results={
                    "spf": "fail",
                    "dkim": "fail",
                    "dmarc": "fail",
                    "domainAge": "14 days",
                    "registrar": "NameCheap Inc."
                },
                hop_timeline=[
                    {"step": 1, "server": "mail.sketchy-relay.net", "ip": "185.220.101.4", "timestamp": "2026-09-07T14:30:00Z", "malicious": True},
                    {"step": 2, "server": "mx.gmail.com", "ip": "142.250.1.27", "timestamp": "2026-09-07T14:30:02Z", "malicious": False}
                ],
                geojson_map={
                    "type": "FeatureCollection",
                    "features": [
                        {"type": "Feature", "geometry": {"type": "Point", "coordinates": [8.68, 50.11]}, "properties": {"hop": 1, "ip": "185.220.101.4", "city": "Frankfurt", "malicious": True}},
                        {"type": "Feature", "geometry": {"type": "LineString", "coordinates": [[8.68, 50.11], [77.59, 12.97]]}, "properties": {"from": "Frankfurt", "to": "Bengaluru"}}
                    ]
                },
                attack_graph={
                    "nodes": [
                        {"id": "sender", "label": "attacker@sketchy-relay.net", "type": "sender", "malicious": True},
                        {"id": "hop1", "label": "185.220.101.4 (Frankfurt)", "type": "relay", "malicious": True},
                        {"id": "victim", "label": "victim@corporate-domain.com", "type": "recipient", "malicious": False}
                    ],
                    "edges": [
                        {"from": "sender", "to": "hop1"},
                        {"from": "hop1", "to": "victim"}
                    ]
                },
                threat_results=[
                    {"type": "ip", "value": "185.220.101.4", "reputation": 92, "geo": "Frankfurt, Germany", "malicious": True},
                    {"type": "url", "value": "http://paypa1-secure.com/login", "reputation": 95, "geo": "Germany", "malicious": True}
                ]
            )
            db.add(demo_inv_1)
            logger.info(f"Seeded demo investigation: {inv_id_1}")

        # Case B: Legitimate Internshala Outreach (Clean/Safe)
        inv_id_2 = "inv_internshala_demo_02"
        if not db.query(Investigation).filter(Investigation.id == inv_id_2).first():
            demo_inv_2 = Investigation(
                id=inv_id_2,
                status="complete",
                sender="student-success@internshala.com",
                recipient="candidate@gmail.com",
                subject="Internshala: Important updates regarding your application",
                received_at=datetime.now(timezone.utc),
                domain="internshala.com",
                ip="142.250.190.46",
                city="Bengaluru",
                country="India",
                phishing_score=12,
                verdict="safe",
                risk_level="Low",
                explanation="Authentic corporate communication. Cryptographic SPF and DKIM signatures verified with official Internshala MX records.",
                evidence_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                action_items=[
                    "No remediation required — legitimate student communications.",
                    "Origin and DKIM signatures verified against authenticated Google Workspace MX."
                ],
                raw_headers="Received: from mail-ed1-f46.google.com (142.250.190.46)\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass",
                body_text="Hi Candidate, your application for Cybersecurity Analyst Intern was reviewed. Log in to Internshala to see employer feedback.",
                entities={
                    "urls": ["https://internshala.com/student/dashboard"],
                    "ips": ["142.250.190.46"],
                    "domains": ["internshala.com"]
                },
                auth_results={
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                    "domainAge": "4300 days",
                    "registrar": "GoDaddy.com LLC"
                },
                hop_timeline=[
                    {"step": 1, "server": "mail-ed1-f46.google.com", "ip": "142.250.190.46", "timestamp": "2026-09-08T09:15:00Z", "malicious": False}
                ],
                geojson_map={
                    "type": "FeatureCollection",
                    "features": [
                        {"type": "Feature", "geometry": {"type": "Point", "coordinates": [77.5946, 12.9716]}, "properties": {"hop": 1, "ip": "142.250.190.46", "city": "Bengaluru", "malicious": False}}
                    ]
                },
                attack_graph={
                    "nodes": [
                        {"id": "sender", "label": "student-success@internshala.com", "type": "sender", "malicious": False},
                        {"id": "recipient", "label": "candidate@gmail.com", "type": "recipient", "malicious": False}
                    ],
                    "edges": [
                        {"from": "sender", "to": "recipient"}
                    ]
                },
                threat_results=[
                    {"type": "ip", "value": "142.250.190.46", "reputation": 0, "geo": "Bengaluru, India", "malicious": False}
                ]
            )
            db.add(demo_inv_2)
            logger.info(f"Seeded demo investigation: {inv_id_2}")

        # Case C: BEC Executive Wire Transfer Fraud
        inv_id_3 = "inv_bec_wire_demo_03"
        if not db.query(Investigation).filter(Investigation.id == inv_id_3).first():
            demo_inv_3 = Investigation(
                id=inv_id_3,
                status="complete",
                sender="ceo@exec-corp-global.com",
                recipient="finance@corporate-domain.com",
                subject="URGENT: Confidential Acquisition Escrow Wire Transfer",
                received_at=datetime.now(timezone.utc),
                domain="exec-corp-global.com",
                ip="197.210.64.12",
                city="Lagos",
                country="Nigeria",
                phishing_score=91,
                verdict="phishing",
                risk_level="Critical",
                explanation="High-impact Business Email Compromise (BEC) fraud. Display name spoofing of Chief Executive Officer with unauthorized offshore payment instructions.",
                evidence_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                action_items=[
                    "HALT any outgoing financial transfers immediately.",
                    "Verify transaction requests via verified out-of-band telephone call to CEO.",
                    "Flag and quarantine domain exec-corp-global.com across all mailboxes.",
                    "Audit M365 tenant mail forwarding and inbox rules for compromise indicators."
                ],
                raw_headers="Received: from mail.free-smtp-relay.org (197.210.64.12)\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail",
                body_text="Finance Team, please process the pending $84,500 escrow wire immediately to our legal counsel. Do not discuss over phone as deal is under NDA.",
                entities={
                    "urls": [],
                    "ips": ["197.210.64.12"],
                    "domains": ["exec-corp-global.com"],
                    "senderClaim": "CEO Office <ceo@corporate-domain.com>",
                    "senderActual": "ceo@exec-corp-global.com"
                },
                auth_results={
                    "spf": "fail",
                    "dkim": "none",
                    "dmarc": "fail"
                },
                hop_timeline=[
                    {"step": 1, "server": "mail.free-smtp-relay.org", "ip": "197.210.64.12", "timestamp": "2026-09-08T11:00:00Z", "malicious": True}
                ],
                geojson_map={
                    "type": "FeatureCollection",
                    "features": [
                        {"type": "Feature", "geometry": {"type": "Point", "coordinates": [3.3792, 6.5244]}, "properties": {"hop": 1, "ip": "197.210.64.12", "city": "Lagos", "malicious": True}}
                    ]
                },
                attack_graph={
                    "nodes": [
                        {"id": "sender", "label": "ceo@exec-corp-global.com", "type": "sender", "malicious": True},
                        {"id": "recipient", "label": "finance@corporate-domain.com", "type": "recipient", "malicious": False}
                    ],
                    "edges": [
                        {"from": "sender", "to": "recipient"}
                    ]
                },
                threat_results=[
                    {"type": "ip", "value": "197.210.64.12", "reputation": 89, "geo": "Lagos, Nigeria", "malicious": True}
                ]
            )
            db.add(demo_inv_3)
            logger.info(f"Seeded demo investigation: {inv_id_3}")

        db.commit()


    except Exception as e:
        logger.error(f"Seeding error: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
