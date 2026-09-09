"""
TraceMail AI Backend — User Model
"""
from backend.database.connection import Base, Column, String, Boolean, DateTime
from backend.utils.helpers import generate_uuid, utc_now


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, default=lambda: generate_uuid("usr_"), index=True)
    email = Column(String(255), default="", index=True, nullable=False)
    hashed_password = Column(String(255), default="", nullable=False)
    name = Column(String(100), default="Analyst", nullable=True)
    role = Column(String(50), default="analyst", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
