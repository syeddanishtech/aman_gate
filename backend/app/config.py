"""Runtime configuration. All secrets come from the environment; demo defaults are
clearly marked NONPRODUCTION and the app refuses to start in production mode with them."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent

DEMO_JWT_SECRET = "nonproduction-demo-jwt-secret-change-me-0001"
DEMO_AUDIT_KEY = "nonproduction-demo-audit-hmac-key-change-me-0001"


def _load_dotenv() -> None:
    """Minimal .env loader (no extra dependency). Existing env vars win."""
    env_file = ROOT_DIR / ".env"
    if not env_file.exists():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


@dataclass(frozen=True)
class Settings:
    env: str = field(default_factory=lambda: os.getenv("AMAN_ENV", "demo"))
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "AMAN_DATABASE_URL", f"sqlite:///{(BACKEND_DIR / 'data' / 'aman_gate.db').as_posix()}"
        )
    )
    jwt_secret: str = field(default_factory=lambda: os.getenv("AMAN_JWT_SECRET", DEMO_JWT_SECRET))
    jwt_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("AMAN_JWT_TTL_SECONDS", "3600")))
    audit_hmac_key: str = field(default_factory=lambda: os.getenv("AMAN_AUDIT_HMAC_KEY", DEMO_AUDIT_KEY))
    demo_password: str = field(default_factory=lambda: os.getenv("AMAN_DEMO_PASSWORD", "Lab-Only-Demo-2026!"))
    demo_quick_login: bool = field(
        default_factory=lambda: os.getenv("AMAN_DEMO_QUICK_LOGIN", "true").lower() == "true"
    )
    enable_baseline_lab: bool = field(
        default_factory=lambda: os.getenv("AMAN_ENABLE_BASELINE_LAB", "true").lower() == "true"
    )
    approval_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("AMAN_APPROVAL_TTL_SECONDS", "900")))
    max_upload_bytes: int = field(default_factory=lambda: int(os.getenv("AMAN_MAX_UPLOAD_BYTES", str(256 * 1024))))
    upload_dir: Path = field(default_factory=lambda: BACKEND_DIR / "data" / "uploads")
    model_dir: Path = field(default_factory=lambda: BACKEND_DIR / "ml_artifacts")
    frontend_dist: Path = field(default_factory=lambda: ROOT_DIR / "frontend" / "dist")
    tenant_id: str = "northbridge"

    @property
    def is_demo(self) -> bool:
        return self.env != "production"

    def validate(self) -> None:
        if not self.is_demo:
            if self.jwt_secret == DEMO_JWT_SECRET or self.audit_hmac_key == DEMO_AUDIT_KEY:
                raise RuntimeError("Refusing to start: demo secrets are not allowed when AMAN_ENV=production")
            if self.demo_quick_login or self.enable_baseline_lab:
                raise RuntimeError("Refusing to start: quick login / baseline lab must be disabled in production")
        if len(self.jwt_secret) < 32 or len(self.audit_hmac_key) < 32:
            raise RuntimeError("Secrets must be at least 32 characters")


settings = Settings()
