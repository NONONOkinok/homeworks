"""
Случайный Refresh Token и его отпечаток.

Простыми словами. Refresh Token — длинный случайный пароль сессии, не записка
JWT. В базу попадает только отпечаток. По отпечатку нельзя восстановить сам
пароль, но предъявленный пароль можно снова отпечатать и сравнить.

Argon2 здесь не используется: он нужен для паролей, которые человек в состоянии
запомнить. У этой строки 256 случайных бит, поэтому достаточно SHA-256.
"""

from __future__ import annotations

import hashlib
import secrets

REFRESH_TOKEN_BYTES = 32
REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60


def generate_refresh_token() -> str:
    """Возвращает новую непрозрачную строку. Это не JWT."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Детерминированный отпечаток. В SQLite хранится только он."""
    if not isinstance(token, str) or token == "":
        raise ValueError("Нужна непустая строка токена")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hashes_match(left: str, right: str) -> bool:
    """Сравнение отпечатков без досрочного выхода по первому отличию."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return secrets.compare_digest(left, right)
