"""
Первый выпуск Refresh Token.

Исходная строка записывается в хранилище секретов. В SQLite попадает хеш и
срок: 7 дней, без продления. Повторный выпуск для той же сессии отказывается.
Замена старого токена, обнаружение повторной сдачи и отзыв сессии здесь не делаются.

Порядок такой: сначала черновик с хешем, затем секрет, и только после повторного
чтения секрета черновик становится действующим. Если связка паролей не ответила,
действующей записи не остаётся.
"""

from __future__ import annotations

import sqlite3
import uuid

from secret_store import (
    SecretStore,
    SecretStoreError,
    delete_refresh_secret,
    load_refresh_secret,
    save_refresh_secret,
)
from security import (
    REFRESH_TTL_SECONDS,
    generate_refresh_token,
    hash_refresh_token,
    hashes_match,
)


class RefreshTokenError(Exception):
    """Токен отклонён. Текст для человека не содержит сам токен."""

    def __init__(self, code: str):
        self.code = code
        super().__init__("Токен обновления отклонён")


def issue_refresh_token(
    conn: sqlite3.Connection,
    store: SecretStore,
    session_id: str,
    now: int | None = None,
) -> dict:
    """Создаёт один действующий Refresh Token для уже активной сессии."""
    issued_at = _clock(now)
    _require_active_session(conn, session_id)
    if _current_token_id(conn, session_id) is not None:
        raise RefreshTokenError("already_issued")

    token_id = str(uuid.uuid4())
    raw = generate_refresh_token()
    digest = hash_refresh_token(raw)
    expires_at = issued_at + REFRESH_TTL_SECONDS
    conn.execute(
        """
        INSERT INTO refresh_tokens (
            id, session_id, token_hash, issued_at, expires_at, state
        ) VALUES (?, ?, ?, ?, ?, 'staged')
        """,
        (token_id, session_id, digest, issued_at, expires_at),
    )
    conn.commit()

    try:
        save_refresh_secret(store, token_id, raw)
        stored = load_refresh_secret(store, token_id)
    except SecretStoreError:
        _abandon(conn, store, token_id)
        raise
    if stored is None or not hashes_match(stored, raw):
        _abandon(conn, store, token_id)
        raise RefreshTokenError("storage")

    try:
        updated = conn.execute(
            """
            UPDATE refresh_tokens
            SET state = 'current'
            WHERE id = ? AND state = 'staged'
            """,
            (token_id,),
        )
        if updated.rowcount != 1:
            raise RefreshTokenError("storage")
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        _abandon(conn, store, token_id)
        raise RefreshTokenError("already_issued") from None
    except RefreshTokenError:
        _abandon(conn, store, token_id)
        raise

    return {
        "token_id": token_id,
        "session_id": session_id,
        "refresh_token": raw,
        "expires_at": expires_at,
    }


def verify_refresh_token(
    conn: sqlite3.Connection,
    store: SecretStore,
    refresh_token: str,
    now: int | None = None,
) -> dict:
    """
    Проверяет предъявленную строку.

    Неизвестный токен не меняет сессии. Состояние сессии эта функция не отзывает.
    """
    checked_at = _clock(now)
    if not isinstance(refresh_token, str) or refresh_token == "":
        raise RefreshTokenError("unknown")
    digest = hash_refresh_token(refresh_token)
    row = conn.execute(
        """
        SELECT id, session_id, token_hash, expires_at, state
        FROM refresh_tokens
        WHERE token_hash = ?
        """,
        (digest,),
    ).fetchone()
    if row is None or not hashes_match(row["token_hash"], digest):
        raise RefreshTokenError("unknown")
    if row["state"] != "current":
        raise RefreshTokenError("not_current")
    if row["expires_at"] <= checked_at:
        raise RefreshTokenError("expired")

    stored = load_refresh_secret(store, row["id"])
    if stored is None or not hashes_match(stored, refresh_token):
        raise RefreshTokenError("storage")
    return {
        "token_id": row["id"],
        "session_id": row["session_id"],
        "expires_at": row["expires_at"],
    }


def _require_active_session(conn: sqlite3.Connection, session_id: str) -> None:
    if not isinstance(session_id, str) or session_id.strip() == "":
        raise RefreshTokenError("no_session")
    row = conn.execute(
        "SELECT state FROM sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    if row is None or row["state"] != "active":
        raise RefreshTokenError("no_session")


def _current_token_id(conn: sqlite3.Connection, session_id: str) -> str | None:
    row = conn.execute(
        """
        SELECT id FROM refresh_tokens
        WHERE session_id = ? AND state = 'current'
        """,
        (session_id,),
    ).fetchone()
    return None if row is None else row["id"]


def _abandon(conn: sqlite3.Connection, store: SecretStore, token_id: str) -> None:
    """Черновик не становится действующим. Секрет этого поколения убирается."""
    try:
        delete_refresh_secret(store, token_id)
    except SecretStoreError:
        pass
    conn.execute(
        """
        UPDATE refresh_tokens
        SET state = 'discarded'
        WHERE id = ? AND state = 'staged'
        """,
        (token_id,),
    )
    conn.commit()


def _clock(now: int | None) -> int:
    if now is None:
        import time
        return int(time.time())
    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("Время токена должно быть целым числом секунд")
    return now
