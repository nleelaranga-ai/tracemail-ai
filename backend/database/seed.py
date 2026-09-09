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

        # 2. Seed Master Investigation Case (Paypal Credential Phish from Section 6)
        inv_id = "inv_paypal_phish_demo_01"
        existing_inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if not existing_inv:
            demo_inv = Investigation(
                id=inv_id,
                status="complete",
                sender="support@paypal-security-update.com",
                recipient="victim@corporate-domain.com",
                subject="URGENT: Unauthorized access detected - Verify Identity",
                received_at=datetime.now(timezone.utc),
                phishing_score=94,
                verdict="phishing",
                explanation="Critical credential harvesting campaign. Deceptive lookalike domain 'paypa1-secure.com' detected, failing SPF/DMARC authentication.",
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
            db.add(demo_inv)
            db.commit()
            logger.info(f"Seeded demo investigation: {inv_id}")

    except Exception as e:
        logger.error(f"Seeding error: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
