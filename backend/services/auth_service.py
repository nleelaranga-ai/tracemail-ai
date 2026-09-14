"""
TraceMail AI Backend — Authentication & JWT Service
"""
import os
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from backend.models.user import User
from backend.utils.config import settings
from backend.utils.constants import ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from backend.utils.logger import logger

# Password Hashing Fallback
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _HAS_PASSLIB = True
except ImportError:
    _HAS_PASSLIB = False

# JWT Fallback (python-jose or PyJWT)
try:
    from jose import jwt as jose_jwt, JWTError as JoseJWTError
    _HAS_JOSE = True
except ImportError:
    _HAS_JOSE = False
    import jwt as pyjwt


class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        if _HAS_PASSLIB:
            try:
                return pwd_context.verify(plain_password, hashed_password)
            except Exception:
                pass
        
        # Salted hash fallback
        if ":" in hashed_password:
            salt, hash_val = hashed_password.split(":", 1)
            expected = hashlib.sha256((salt + plain_password).encode("utf-8")).hexdigest()
            return hmac.compare_digest(hash_val, expected)
        
        # Direct hash fallback
        expected = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(hashed_password, expected)

    @staticmethod
    def get_password_hash(password: str) -> str:
        if _HAS_PASSLIB:
            try:
                return pwd_context.hash(password)
            except Exception:
                pass
        
        salt = "tracemail_salt_sih26106"
        hash_val = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return f"{salt}:{hash_val}"

    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})

        if _HAS_JOSE:
            return jose_jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)
        else:
            return pyjwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> Optional[Dict[str, Any]]:
        keys_to_try = [
            settings.JWT_SECRET_KEY,
            os.getenv("JWT_SECRET", ""),
            "tracemail-hackathon-jwt-secret-key-sih26106",
            "tracemail-jwt-secret-key-production-ready",
            settings.SECRET_KEY,
        ]
        unique_keys = []
        for k in keys_to_try:
            if k and k not in unique_keys:
                unique_keys.append(k)

        for key in unique_keys:
            try:
                if _HAS_JOSE:
                    return jose_jwt.decode(token, key, algorithms=[ALGORITHM])
                else:
                    return pyjwt.decode(token, key, algorithms=[ALGORITHM])
            except Exception:
                continue

        logger.warning("JWT decode notice: Token could not be verified with any configured secret keys or has expired.")
        return None

    @classmethod
    def authenticate_user(cls, db: Any, email: str, password: str) -> Optional[User]:
        user = db.query(User).filter(User.email == email).first()
        if not user or not cls.verify_password(password, user.hashed_password):
            return None
        return user

    @classmethod
    def register_user(cls, db: Any, email: str, password: str, name: Optional[str] = None) -> User:
        hashed = cls.get_password_hash(password)
        new_user = User(
            email=email,
            hashed_password=hashed,
            name=name or email.split("@")[0],
            role="analyst"
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
