"""Idempotent database bootstrap and demo reset."""
from __future__ import annotations

from sqlalchemy import func, select

from .db import SessionLocal, create_schema, drop_schema
from .models import User
from .seed import seed


def ensure_seeded() -> None:
    create_schema()
    s = SessionLocal()
    try:
        if s.execute(select(func.count(User.id))).scalar_one() == 0:
            seed(s)
    finally:
        s.close()


def reset_demo() -> None:
    drop_schema()
    create_schema()
    s = SessionLocal()
    try:
        seed(s)
    finally:
        s.close()
