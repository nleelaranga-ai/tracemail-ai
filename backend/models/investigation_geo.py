"""
TraceMail AI Backend — Investigation Geospatial Cache Model
Stores geocoding, routing, and nearby infrastructure lookups with TTL expiry.
"""
from datetime import datetime, timedelta
from backend.database.connection import Base, Column, String, DateTime, JSON
from backend.utils.helpers import utc_now


class InvestigationGeoCache(Base):
    __tablename__ = "investigation_geo_cache"

    key = Column(String(255), primary_key=True, index=True)
    cache_type = Column(String(50), default="geocode", index=True)  # geocode, reverse, route, places, ip
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False, default=lambda: utc_now() + timedelta(days=30))

    def is_expired(self) -> bool:
        return utc_now() > self.expires_at
