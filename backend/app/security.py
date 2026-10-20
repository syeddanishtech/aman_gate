"""Authentication. The JWT only proves the user id (sub). Role and tenant are always re-read from the
database, so a token carrying a different role claim cannot escalate privileges."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import User

ALGORITHM = "HS256"
ISSUER = "aman-gate-lab"
AUDIENCE = "aman-gate-api"
ROLES = ("procurement_officer", "junior_clerk", "finance_manager", "security_analyst")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, dk_hex = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(dk.hex(), dk_hex)


def issue_token(user: User) -> str:
    now = int(time.time())
    payload = {
        "sub": user.id,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + settings.jwt_ttl_seconds,
        "jti": secrets.token_hex(8),
        # Display hint only. The server never authorises from this claim.
        "role_hint": user.role,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


@dataclass(frozen=True)
class Identity:
    user_id: str
    username: str
    display_name: str
    role: str
    tenant_id: str


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail={"code": detail}, headers={"WWW-Authenticate": "Bearer"})


def current_identity(request: Request, db: Session = Depends(get_db)) -> Identity:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise _unauthorized("AUTH_MISSING_TOKEN")
    token = auth[7:].strip()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],  # pinned: rejects alg=none and algorithm confusion
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("AUTH_TOKEN_EXPIRED")
    except jwt.PyJWTError:
        raise _unauthorized("AUTH_INVALID_TOKEN")
    user = db.get(User, claims["sub"])
    if user is None or not user.active:
        raise _unauthorized("AUTH_UNKNOWN_SUBJECT")
    if user.role not in ROLES:
        raise _unauthorized("AUTH_INVALID_ROLE")
    return Identity(user.id, user.username, user.display_name, user.role, user.tenant_id)


def require_roles(*roles: str):
    def dep(identity: Identity = Depends(current_identity)) -> Identity:
        if identity.role not in roles:
            raise HTTPException(status_code=403, detail={"code": "ROLE_NOT_PERMITTED", "required": list(roles)})
        return identity

    return dep
