"""Output assurance (AMAN Gate 2.0, WP3): check a model reply, then locally restore only what the caller's
role and purpose may see. Deterministic checks decide; advisory flags never act as an access boundary.

`router` is not mounted by this package: include it from app.main when WP3 is wired in.
"""
from .routes import router

__all__ = ["router"]
