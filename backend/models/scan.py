"""
TraceMail AI Backend — Investigation & Scan Models
"""
from backend.database.connection import Base, Column, String, Integer, DateTime, Text, JSON
from backend.utils.helpers import generate_uuid, utc_now


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("inv_"), index=True)
    status = Column(String(50), default="processing", nullable=False)
    sender = Column(String(255), default="", nullable=True)
    recipient = Column(String(255), default="", nullable=True)
    subject = Column(String(500), default="", nullable=True)
    received_at = Column(DateTime, default=utc_now, nullable=False)
    
    domain = Column(String(255), default="", nullable=True)
    ip = Column(String(64), default="", nullable=True)
    country = Column(String(100), default="Unknown", nullable=True)
    city = Column(String(100), default="Unknown", nullable=True)
    latitude = Column(JSON, default=0.0, nullable=True)
    longitude = Column(JSON, default=0.0, nullable=True)
    
    phishing_score = Column(Integer, default=0, nullable=False)
    verdict = Column(String(50), default="suspicious", nullable=False)
    risk_level = Column(String(50), default="Medium", nullable=False)
    explanation = Column(Text, default="", nullable=True)
    ai_summary = Column(Text, default="", nullable=True)
    
    raw_headers = Column(Text, default="", nullable=True)
    body_text = Column(Text, default="", nullable=True)
    entities = Column(JSON, default=dict, nullable=True)
    auth_results = Column(JSON, default=dict, nullable=True)
    hop_timeline = Column(JSON, default=list, nullable=True)
    timeline = Column(JSON, default=list, nullable=True)
    geojson_map = Column(JSON, default=dict, nullable=True)
    attack_graph = Column(JSON, default=dict, nullable=True)
    threat_results = Column(JSON, default=list, nullable=True)
    
    virus_total = Column(JSON, default=dict, nullable=True)
    abuse_ipdb = Column(JSON, default=dict, nullable=True)
    whois = Column(JSON, default=dict, nullable=True)
    dns = Column(JSON, default=dict, nullable=True)
    urlscan = Column(JSON, default=dict, nullable=True)
    ai_analysis = Column(JSON, default=dict, nullable=True)
    ioc = Column(JSON, default=list, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, nullable=False)

    @property
    def threat_score(self):
        return self.phishing_score

    @threat_score.setter
    def threat_score(self, val):
        self.phishing_score = val

    @property
    def origin_ip(self):
        return self.ip

    @origin_ip.setter
    def origin_ip(self, val):
        self.ip = val

    @property
    def origin_city(self):
        return self.city

    @origin_city.setter
    def origin_city(self, val):
        self.city = val

    @property
    def origin_country(self):
        return self.country

    @origin_country.setter
    def origin_country(self, val):
        self.country = val

    @property
    def iocs(self):
        return self.ioc

    @iocs.setter
    def iocs(self, val):
        self.ioc = val

    @property
    def threat_intel(self):
        return {
            "virustotal": self.virus_total or {},
            "abuseipdb": self.abuse_ipdb or {},
            "whois": self.whois or {},
            "dns": self.dns or {},
            "urlscan": self.urlscan or {},
            "geoip": {
                "ip": self.ip,
                "city": self.city,
                "country": self.country,
                "latitude": self.latitude,
                "longitude": self.longitude
            }
        }


class EmailRecord(Base):
    __tablename__ = "emails"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("eml_"), index=True)
    scan_id = Column(String(64), index=True, nullable=False)
    sender = Column(String(255), default="", nullable=True)
    recipient = Column(String(255), default="", nullable=True)
    subject = Column(String(500), default="", nullable=True)
    message_id = Column(String(255), default="", nullable=True)
    reply_to = Column(String(255), default="", nullable=True)
    raw_eml = Column(Text, default="", nullable=True)
    body_plain = Column(Text, default="", nullable=True)
    body_html = Column(Text, default="", nullable=True)
    date_sent = Column(DateTime, default=utc_now, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("scan_"), index=True)
    scan_id = Column(String(64), index=True, nullable=False)
    sender = Column(String(255), default="", nullable=True)
    domain = Column(String(255), default="", nullable=True)
    ip = Column(String(64), default="", nullable=True)
    country = Column(String(100), default="", nullable=True)
    city = Column(String(100), default="", nullable=True)
    latitude = Column(JSON, default=0.0, nullable=True)
    longitude = Column(JSON, default=0.0, nullable=True)
    threat_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(50), default="Low", nullable=False)
    status = Column(String(50), default="complete", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class AIResultRecord(Base):
    __tablename__ = "ai_results"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("ai_"), index=True)
    scan_id = Column(String(64), index=True, nullable=False)
    prediction = Column(String(50), default="Suspicious", nullable=False)
    confidence = Column(JSON, default=0.0, nullable=False)
    summary = Column(Text, default="", nullable=True)
    reasons_json = Column(JSON, default=list, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

