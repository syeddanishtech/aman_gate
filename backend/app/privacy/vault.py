"""Local-only token vault: the pseudonym -> original mapping, encrypted at rest (AMAN Gate 2.0, WP3).

WP1 hands back a SafeArtifact whose `rehydration_table` is the one thing that can turn pseudonyms such as
[PERSON_01] back into personal data. This module is the only place that table is persisted, and it is
never persisted in the clear. There is no network code here and nothing in this package imports any.

Cryptography (vetted primitives from the `cryptography` package; nothing is hand-rolled)
  * Master secret: a high-entropy string read from AMAN_VAULT_MASTER_SECRET at call time (so the project's
    .env loader and test monkeypatching both work). The built-in default is a labelled NONPRODUCTION
    demo value; AMAN_ENV=production refuses it, and any secret under 32 characters is refused.
  * Key derivation: HKDF-SHA256 (RFC 5869). IKM = master secret, salt = the session's own random 32-byte
    salt, info = format label + PURPOSE. So there is one key per (session, purpose); a purpose cannot open
    another purpose's records, and no two sessions share a key. No key is stored or hard-coded.
  * Encryption: AES-256-GCM with a fresh random 96-bit nonce for every record. Nonce reuse under one key
    is catastrophic for GCM, so the database also enforces UNIQUE(session, nonce): a repeat is a hard
    failure, never a silent reuse. (Random 96-bit nonces stay safe far below the 2^32-per-key bound;
    one key here protects at most a few thousand records.)
  * Associated data binds each ciphertext to (format, tenant, session, token, role, purpose). The
    associated data is rebuilt from the REQUEST at lookup time, not read back from the row, so moving a
    ciphertext to another token/session/role/purpose, or editing those columns, fails authentication.
  * Any authentication failure (wrong key, tampered ciphertext, truncated record, moved or edited row)
    raises VaultAuthError. Callers must treat it as "no original available", never retry with a guess.

Access control (deterministic; nothing here consults a model)
  An entry is stored per (session, token, role, purpose). A lookup needs ALL of: same tenant, an
  unexpired session, a token that was issued for that session, a role whose class grant (ROLE_CLASS_GRANTS)
  covers the token's class, and an entry stored for exactly that role and purpose. Unknown tenants,
  sessions, roles and purposes all fail closed. RESTRICTED values, the canary and placeholder-shaped
  strings can never be stored.

Limits: GCM does not hide plaintext length; Python cannot wipe strings from memory; the master secret
lives in the environment and there is no key rotation yet (an HSM/KMS is the production answer);
ROLE_CLASS_GRANTS is an illustrative lab policy; scoping is by role and declared purpose, not by user.
Pseudonymization is reversible by design and remains a privacy control, not a guarantee that no one can
be re-identified.
"""
from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .detectors import TOKEN_RE, detect
from .policy import DEFAULT_POLICY, EXPORT_ALLOWED, PrivacyPolicy
from .sanitize import SafeArtifact
from .vault_models import VaultEntry, VaultSession, create_vault_schema

VAULT_SECRET_ENV = "AMAN_VAULT_MASTER_SECRET"
VAULT_TTL_ENV = "AMAN_VAULT_TTL_SECONDS"
# NONPRODUCTION: lab default so the demo runs offline with zero setup. AMAN_ENV=production refuses it.
DEMO_VAULT_MASTER_SECRET = "nonproduction-demo-vault-master-secret-change-me-0001"
MIN_SECRET_CHARS = 32

FORMAT_VERSION = "aman-vault-v1"
ALG_LABEL = "AES-256-GCM/HKDF-SHA256/v1"
_KDF_LABEL = b"aman-gate/token-vault/key/v1"
KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12
SALT_BYTES = 32
MAX_ORIGINAL_CHARS = 4096

DEFAULT_PURPOSE = "display_to_requester"
DEFAULT_TTL_SECONDS = 8 * 3600
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 7 * 24 * 3600

REHYDRATION_POLICY_ID = "POL-REHYDRATION-v1"
# Which pseudonym classes each role may EVER get the original of. Illustrative lab policy (synthetic roles):
# least privilege, deterministic, fail closed (a role or class not listed gets nothing). A real deployment
# would derive this from its own RBAC / document ACLs.
ROLE_CLASS_GRANTS: Mapping[str, frozenset[str]] = MappingProxyType({
    "finance_manager": frozenset({"ORG", "PERSON", "EMAIL", "PHONE", "ID", "ACCOUNT"}),
    "procurement_officer": frozenset({"ORG", "PERSON", "EMAIL", "PHONE"}),
    "junior_clerk": frozenset({"ORG"}),
    "security_analyst": frozenset(),  # reviews pseudonymized evidence and audit records only
})

PURPOSE_RE = re.compile(r"^[a-z][a-z0-9_.\-]{2,63}$")
SESSION_ID_RE = re.compile(r"^VS-[0-9a-f]{32}$")
ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$")
# ASCII-only on purpose: the vault key space must not contain Unicode look-alikes of a placeholder.
PSEUDONYM_RE = re.compile(r"^\[([A-Z]+)_([0-9]{2,})\]$")
ISSUED_TOKEN_RE = re.compile(r"\[(?:[A-Z]+_[0-9]{2,}|REDACTED:[A-Z_]+)\]")


# ---------------------------------------------------------------------------- errors
class VaultError(Exception):
    """Base class. `code` is a stable machine-readable reason; messages never contain original values."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


class VaultConfigError(VaultError):
    """The master secret is missing, too short, or a demo value in production."""


class VaultAccessError(VaultError):
    """Not found, expired, out of scope, or not granted. Fail closed: no original is returned."""


class VaultAuthError(VaultError):
    """AES-GCM authentication failed: wrong key, tampered or truncated ciphertext, or a moved/edited row."""


# ---------------------------------------------------------------------------- primitives
def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _pack(*parts: bytes) -> bytes:
    """Injective encoding of several fields (length-prefixed), so no two field lists share an encoding."""
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def load_master_secret() -> bytes:
    """The HKDF input keying material. Raises VaultConfigError rather than ever using a weak secret."""
    secret = os.environ.get(VAULT_SECRET_ENV, DEMO_VAULT_MASTER_SECRET)
    if os.environ.get("AMAN_ENV", "demo") == "production" and secret == DEMO_VAULT_MASTER_SECRET:
        raise VaultConfigError("DEMO_SECRET_IN_PRODUCTION", f"set {VAULT_SECRET_ENV} to a random secret")
    if len(secret) < MIN_SECRET_CHARS:
        raise VaultConfigError("SECRET_TOO_SHORT", f"{VAULT_SECRET_ENV} must be at least {MIN_SECRET_CHARS} characters")
    return secret.encode("utf-8")


def derive_key(master: bytes, *, salt: bytes, purpose: str) -> bytes:
    """HKDF-SHA256: one 256-bit key per (master, salt, purpose)."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_BYTES:
        raise VaultError("BAD_SALT")
    if not isinstance(purpose, str) or not PURPOSE_RE.fullmatch(purpose):
        raise VaultError("BAD_PURPOSE")
    info = _pack(_KDF_LABEL, purpose.encode("ascii"))
    return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=bytes(salt), info=info).derive(master)


def build_aad(*, tenant_id: str, session_id: str, token: str, role: str, purpose: str) -> bytes:
    """Associated data: what a ciphertext is bound to. Authenticated, not encrypted."""
    return _pack(*(s.encode("utf-8") for s in (FORMAT_VERSION, tenant_id, session_id, token, role, purpose)))


def seal(plaintext: bytes, *, key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt with a fresh random nonce. Returns (nonce, ciphertext || tag)."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(nonce: bytes, ciphertext: bytes, *, key: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt + authenticate. Any failure is a VaultAuthError, whatever the cause."""
    try:
        return AESGCM(key).decrypt(bytes(nonce), bytes(ciphertext), aad)
    except (InvalidTag, ValueError, TypeError):
        raise VaultAuthError("AUTH_FAILED", "record failed authentication") from None


# ---------------------------------------------------------------------------- screening + policy
def role_may_reveal(role: str, token: str) -> bool:
    """Class-level ceiling: may `role` ever get the original behind `token`? Unknown role/token -> False."""
    m = PSEUDONYM_RE.fullmatch(token) if isinstance(token, str) else None
    return bool(m) and m.group(1) in ROLE_CLASS_GRANTS.get(role, frozenset())


def screen_original(value: str, policy: PrivacyPolicy = DEFAULT_POLICY) -> str | None:
    """Reason code if `value` must never be vaulted or restored, else None.

    Originals behind pseudonyms are CONFIDENTIAL/INTERNAL by nature, so ordinary sensitive types are fine.
    What is never acceptable is a RESTRICTED value or the canary (WP1 redacts these irreversibly; one
    showing up here is a bug or tampering) or anything shaped like a placeholder (it could chain into a
    second rehydration downstream)."""
    if not isinstance(value, str) or not value or len(value) > MAX_ORIGINAL_CHARS:
        return "ORIGINAL_INVALID"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "ORIGINAL_INVALID"
    if TOKEN_RE.search(value):
        return "PLACEHOLDER_SHAPED"
    if any(e.sensitivity == "RESTRICTED" or e.element_type == "CANARY"
           for e in detect(value, vocabulary=policy.vocabulary)):
        return "RESTRICTED_VALUE"
    return None


# ---------------------------------------------------------------------------- results
@dataclass(frozen=True)
class VaultSessionInfo:
    session_id: str
    artifact_id: str | None
    purpose: str
    expires_at: datetime
    issued_count: int  # placeholders present in the artifact (reversible and redacted)
    entries_written: int  # encrypted records written (one per token per granted role)
    entries_by_role: Mapping[str, int]


@dataclass(frozen=True)
class Reveal:
    """Outcome for one token. `code` is "OK" iff `value` is set."""

    token: str
    code: str
    value: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class VaultContext:
    """A resolved, tenant-checked, unexpired vault session, ready to answer role/purpose-scoped lookups."""

    session_id: str
    tenant_id: str
    purpose: str
    artifact_id: str | None
    artifact_sha256: str
    issued_tokens: frozenset[str]
    expires_at: datetime
    _db: Session = field(repr=False, compare=False, default=None)  # type: ignore[assignment]

    def reveal_many(self, tokens: Iterable[str], *, role: str, purpose: str) -> dict[str, Reveal]:
        """Non-raising batch lookup. A VaultConfigError (bad master secret) still propagates: that is a
        deployment fault, not a per-token outcome."""
        session = self._db.get(VaultSession, self.session_id)
        if session is None or session.tenant_id != self.tenant_id:
            return {t: Reveal(t, "SESSION_NOT_FOUND") for t in tokens}
        return _reveal(self._db, session, tokens, role=role, purpose=purpose)


# ---------------------------------------------------------------------------- store
def _pseudonym_class(token: str) -> str:
    m = PSEUDONYM_RE.fullmatch(token) if isinstance(token, str) else None
    if m is None:
        raise VaultError("BAD_TOKEN", "only reversible pseudonym placeholders can be vaulted")
    return m.group(1)


def _load_session(db: Session, session_id: str, tenant_id: str, now: datetime) -> VaultSession:
    """Unknown id and another tenant's id are indistinguishable (same code), as in check_document_access."""
    if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
        raise VaultAccessError("SESSION_NOT_FOUND")
    row = db.get(VaultSession, session_id)
    if row is None or row.tenant_id != tenant_id:
        raise VaultAccessError("SESSION_NOT_FOUND")
    if row.expires_at <= now:
        raise VaultAccessError("SESSION_EXPIRED")
    return row


def encrypt_store(db: Session, *, session_id: str, token: str, original: str, tenant_id: str, role: str,
                  purpose: str, policy: PrivacyPolicy = DEFAULT_POLICY, now: datetime | None = None,
                  commit: bool = True) -> VaultEntry:
    """Encrypt one original for exactly (session, token, role, purpose) and persist it.

    Refuses: a token that was not issued for the session, a role whose class grant does not cover the
    token, a duplicate scope, and any RESTRICTED/canary/placeholder-shaped original."""
    now = now or _utcnow()
    token_class = _pseudonym_class(token)
    if not isinstance(purpose, str) or not PURPOSE_RE.fullmatch(purpose):
        raise VaultError("BAD_PURPOSE")
    if not isinstance(role, str) or token_class not in ROLE_CLASS_GRANTS.get(role, frozenset()):
        raise VaultAccessError("ROLE_NOT_GRANTED")
    reason = screen_original(original, policy)
    if reason is not None:
        raise VaultError(reason)
    session = _load_session(db, session_id, tenant_id, now)
    if token not in set(session.issued_tokens):
        raise VaultAccessError("TOKEN_NOT_ISSUED")
    if db.execute(select(VaultEntry.id).where(
            VaultEntry.session_id == session_id, VaultEntry.token == token,
            VaultEntry.role == role, VaultEntry.purpose == purpose)).first():
        raise VaultError("ENTRY_EXISTS")

    key = derive_key(load_master_secret(), salt=session.kdf_salt, purpose=purpose)
    aad = build_aad(tenant_id=session.tenant_id, session_id=session_id, token=token, role=role, purpose=purpose)
    nonce, ciphertext = seal(original.encode("utf-8"), key=key, aad=aad)
    entry = VaultEntry(session_id=session_id, token=token, token_class=token_class, role=role, purpose=purpose,
                       alg=ALG_LABEL, nonce=nonce, ciphertext=ciphertext, created_at=now)
    db.add(entry)
    try:
        db.flush()
    except IntegrityError:  # the UNIQUE(session, nonce) / scope constraints: refuse, never reuse a nonce
        db.rollback()
        raise VaultError("STORE_REJECTED", "duplicate scope or nonce") from None
    if commit:
        db.commit()
    return entry


def store_artifact(
    db: Session, artifact: SafeArtifact, *, tenant_id: str, owner_user_id: str, owner_role: str,
    purpose: str = DEFAULT_PURPOSE, grant_roles: Sequence[str] | None = None, artifact_id: str | None = None,
    ttl_seconds: int | None = None, policy: PrivacyPolicy = DEFAULT_POLICY, now: datetime | None = None,
) -> VaultSessionInfo:
    """Vault a SafeArtifact's rehydration table in one atomic transaction and return the session handle.

    `grant_roles` (default: just the owner's role) are the roles that will be able to get originals back;
    each gets its own independently encrypted copy of the entries its class grant covers, so a role
    outside the grant list holds no ciphertext it could even try to open. Blocked artifacts have no
    table and are refused."""
    now = now or _utcnow()
    if not isinstance(artifact, SafeArtifact) or artifact.export_status != EXPORT_ALLOWED:
        raise VaultError("ARTIFACT_NOT_EXPORTABLE", "only an EXPORT_ALLOWED artifact can be vaulted")
    for name, val in (("tenant_id", tenant_id), ("owner_user_id", owner_user_id)):
        if not isinstance(val, str) or not val.strip():
            raise VaultError("BAD_REQUEST", f"{name} is required")
    if owner_role not in ROLE_CLASS_GRANTS:
        raise VaultError("UNKNOWN_ROLE")
    if not isinstance(purpose, str) or not PURPOSE_RE.fullmatch(purpose):
        raise VaultError("BAD_PURPOSE")
    if artifact_id is not None and (not isinstance(artifact_id, str) or not ARTIFACT_ID_RE.fullmatch(artifact_id)):
        raise VaultError("BAD_ARTIFACT_ID")
    roles = list(dict.fromkeys(grant_roles if grant_roles is not None else (owner_role,)))
    if not roles or any(r not in ROLE_CLASS_GRANTS for r in roles):
        raise VaultError("UNKNOWN_ROLE")
    if ttl_seconds is None:
        try:
            ttl_seconds = int(os.environ.get(VAULT_TTL_ENV, DEFAULT_TTL_SECONDS))
        except ValueError:
            ttl_seconds = DEFAULT_TTL_SECONDS
    try:
        ttl = max(MIN_TTL_SECONDS, min(MAX_TTL_SECONDS, int(ttl_seconds)))
    except (TypeError, ValueError):
        raise VaultError("BAD_TTL") from None

    issued = sorted(set(ISSUED_TOKEN_RE.findall(artifact.text)))
    table = dict(artifact.rehydration_table)
    for token in table:
        _pseudonym_class(token)
        if token not in issued:
            raise VaultError("TABLE_NOT_IN_ARTIFACT", "a table entry has no matching placeholder in the safe text")

    session = VaultSession(
        session_id="VS-" + secrets.token_hex(16), tenant_id=tenant_id, owner_user_id=owner_user_id,
        owner_role=owner_role, purpose=purpose, artifact_id=artifact_id, artifact_sha256=artifact.sha256,
        policy_id=REHYDRATION_POLICY_ID, issued_tokens=issued, kdf_salt=secrets.token_bytes(SALT_BYTES),
        created_at=now, expires_at=now + timedelta(seconds=ttl))
    written: dict[str, int] = {r: 0 for r in roles}
    try:
        db.add(session)
        try:
            db.flush()
        except IntegrityError:
            raise VaultError("ARTIFACT_ALREADY_VAULTED", "purge the existing session first") from None
        for token, original in table.items():
            for role in roles:
                if not role_may_reveal(role, token):
                    continue  # policy ceiling: this role never gets this class back, so no copy exists
                encrypt_store(db, session_id=session.session_id, token=token, original=original,
                              tenant_id=tenant_id, role=role, purpose=purpose, policy=policy, now=now,
                              commit=False)
                written[role] += 1
        db.commit()
    except Exception:
        db.rollback()
        raise
    return VaultSessionInfo(session.session_id, artifact_id, purpose, session.expires_at, len(issued),
                            sum(written.values()), MappingProxyType(dict(written)))


# ---------------------------------------------------------------------------- lookup
def _open(session: VaultSession, entry: VaultEntry, *, key: bytes, token: str, role: str, purpose: str) -> str:
    if entry.alg != ALG_LABEL:
        raise VaultAuthError("AUTH_FAILED", "unknown record format")
    aad = build_aad(tenant_id=session.tenant_id, session_id=session.session_id, token=token, role=role,
                    purpose=purpose)
    plaintext = unseal(entry.nonce, entry.ciphertext, key=key, aad=aad)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise VaultAuthError("AUTH_FAILED", "authenticated record is not text") from None


def _reveal(db: Session, session: VaultSession, tokens: Iterable[str], *, role: str, purpose: str) -> dict[str, Reveal]:
    wanted = list(dict.fromkeys(tokens))
    issued = frozenset(session.issued_tokens)
    out: dict[str, Reveal] = {}
    candidates: list[str] = []
    grants = ROLE_CLASS_GRANTS.get(role, frozenset()) if isinstance(role, str) else frozenset()
    for t in wanted:
        m = PSEUDONYM_RE.fullmatch(t) if isinstance(t, str) else None
        if not isinstance(t, str) or t not in issued:
            out[str(t)] = Reveal(str(t), "TOKEN_NOT_ISSUED")
        elif m is None:
            out[t] = Reveal(t, "IRREVERSIBLE")  # e.g. [REDACTED:X]: issued, but nothing was ever stored
        elif m.group(1) not in grants:
            out[t] = Reveal(t, "ROLE_NOT_GRANTED")
        else:
            candidates.append(t)
    if not isinstance(purpose, str) or not PURPOSE_RE.fullmatch(purpose):
        return {**out, **{t: Reveal(t, "NO_ENTRY_FOR_SCOPE") for t in candidates}}

    entries: dict[str, VaultEntry] = {}
    for i in range(0, len(candidates), 500):
        chunk = candidates[i:i + 500]
        for e in db.execute(select(VaultEntry).where(
                VaultEntry.session_id == session.session_id, VaultEntry.role == role,
                VaultEntry.purpose == purpose, VaultEntry.token.in_(chunk))).scalars():
            entries[e.token] = e
    key: bytes | None = None
    for t in candidates:
        entry = entries.get(t)
        if entry is None:
            out[t] = Reveal(t, "NO_ENTRY_FOR_SCOPE")
            continue
        if key is None:
            key = derive_key(load_master_secret(), salt=session.kdf_salt, purpose=purpose)
        try:
            out[t] = Reveal(t, "OK", _open(session, entry, key=key, token=t, role=role, purpose=purpose))
        except VaultAuthError:
            out[t] = Reveal(t, "AUTH_FAILED")
    return out


def decrypt_lookup(db: Session, *, session_id: str, token: str, tenant_id: str, role: str, purpose: str,
                   now: datetime | None = None) -> str:
    """Return the original behind `token`, or raise. VaultAccessError: nothing available for this scope.
    VaultAuthError: an entry exists but failed authentication (wrong key or tampering)."""
    session = _load_session(db, session_id, tenant_id, now or _utcnow())
    res = _reveal(db, session, [token], role=role, purpose=purpose)[str(token)]
    if res.code == "OK" and res.value is not None:
        return res.value
    if res.code == "AUTH_FAILED":
        raise VaultAuthError("AUTH_FAILED", "record failed authentication")
    raise VaultAccessError(res.code)


def open_context(db: Session, *, tenant_id: str, session_id: str | None = None, artifact_id: str | None = None,
                 now: datetime | None = None) -> VaultContext | None:
    """Resolve a session by id and/or artifact id inside `tenant_id`. None when neither is given.
    If both are given they must name the same session. Wrong tenant == unknown (SESSION_NOT_FOUND)."""
    if session_id is None and artifact_id is None:
        return None
    now = now or _utcnow()
    row: VaultSession | None = None
    if session_id is not None:
        if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id):
            raise VaultAccessError("SESSION_NOT_FOUND")
        row = db.get(VaultSession, session_id)
        if row is not None and row.tenant_id != tenant_id:
            row = None
    if artifact_id is not None:
        if not isinstance(artifact_id, str) or not ARTIFACT_ID_RE.fullmatch(artifact_id):
            raise VaultAccessError("SESSION_NOT_FOUND")
        by_artifact = db.execute(select(VaultSession).where(
            VaultSession.tenant_id == tenant_id, VaultSession.artifact_id == artifact_id)).scalar_one_or_none()
        if session_id is None:
            row = by_artifact
        elif by_artifact is None or row is None or by_artifact.session_id != row.session_id:
            row = None
    if row is None:
        raise VaultAccessError("SESSION_NOT_FOUND")
    if row.expires_at <= now:
        raise VaultAccessError("SESSION_EXPIRED")
    return VaultContext(session_id=row.session_id, tenant_id=row.tenant_id, purpose=row.purpose,
                        artifact_id=row.artifact_id, artifact_sha256=row.artifact_sha256,
                        issued_tokens=frozenset(row.issued_tokens), expires_at=row.expires_at, _db=db)


# ---------------------------------------------------------------------------- lifecycle
def purge_session(db: Session, *, session_id: str, tenant_id: str) -> int:
    """Delete a session and every ciphertext in it (the originals become unrecoverable). Returns entries deleted."""
    row = db.get(VaultSession, session_id) if isinstance(session_id, str) else None
    if row is None or row.tenant_id != tenant_id:
        raise VaultAccessError("SESSION_NOT_FOUND")
    n = db.execute(delete(VaultEntry).where(VaultEntry.session_id == session_id)).rowcount or 0
    db.execute(delete(VaultSession).where(VaultSession.session_id == session_id))
    db.commit()
    return n


def purge_expired(db: Session, *, now: datetime | None = None) -> int:
    """Delete every expired session and its ciphertexts. Returns sessions deleted."""
    cutoff = now or _utcnow()
    ids = list(db.execute(select(VaultSession.session_id).where(VaultSession.expires_at <= cutoff)).scalars())
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        db.execute(delete(VaultEntry).where(VaultEntry.session_id.in_(chunk)))
        db.execute(delete(VaultSession).where(VaultSession.session_id.in_(chunk)))
    db.commit()
    return len(ids)


__all__ = [
    "ALG_LABEL", "DEFAULT_PURPOSE", "DEMO_VAULT_MASTER_SECRET", "REHYDRATION_POLICY_ID", "ROLE_CLASS_GRANTS",
    "VAULT_SECRET_ENV", "Reveal", "VaultAccessError", "VaultAuthError", "VaultConfigError", "VaultContext",
    "VaultError", "VaultSessionInfo", "build_aad", "create_vault_schema", "decrypt_lookup", "derive_key",
    "encrypt_store", "load_master_secret", "open_context", "purge_expired", "purge_session", "role_may_reveal",
    "screen_original", "seal", "store_artifact", "unseal",
]
