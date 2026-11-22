"""
Refresh Token: первый выпуск и замена.

Простыми словами. При обновлении старый длинный пароль сессии сдаётся и
сразу перестаёт действовать. Взамен выдаётся новый на семь дней от этого
момента. Если кто-то приносит уже сданный пароль, закрывается только эта
сессия: система видит повтор, но не может понять, кто его принёс.

Технически замена идёт в два шага, потому что SQLite и keyring не умеют
одну общую транзакцию. Сначала в базе появляется черновик, затем секрет
попадает в связку, и только потом одна транзакция SQLite помечает старый
токен использованным, а новый — действующим. Повторное обновление того же
токена ждёт эту транзакцию и вторую пару не создаёт.
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
from token_manager import ACCESS_TTL_SECONDS, issue_access_token
from proof_manager import ProofError, verify_and_consume_proof


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
    session = conn.execute(
        "SELECT state, expires_at FROM sessions WHERE id = ?",
        (row["session_id"],),
    ).fetchone()
    if session is None or session["state"] != "active":
        raise RefreshTokenError("no_session")
    if session["expires_at"] <= checked_at:
        raise RefreshTokenError("expired")

    stored = load_refresh_secret(store, row["id"])
    if stored is None or not hashes_match(stored, refresh_token):
        raise RefreshTokenError("storage")
    return {
        "token_id": row["id"],
        "session_id": row["session_id"],
        "expires_at": row["expires_at"],
    }



def rotate_refresh_token(
    conn: sqlite3.Connection,
    store: SecretStore,
    signing_key: bytes,
    refresh_token: str,
    proof: str,
    now: int | None = None,
) -> dict:
    """Меняет Refresh Token после подтверждения владения ключом сессии."""

    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise ValueError("Секрет HS256 должен быть 32 байтами")

    rotated_at = _clock(now)

    if not isinstance(refresh_token, str) or refresh_token == "":
        _event(conn, rotated_at, "refresh_unknown", "rejected", None, None, None)
        conn.commit()
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
        _event(conn, rotated_at, "refresh_unknown", "rejected", None, None, None)
        conn.commit()
        raise RefreshTokenError("unknown")

    # Получаем сессию и её открытый Proof Key.
    session = conn.execute(
        """
        SELECT s.user_id, s.state, s.expires_at,
               s.proof_public_key, u.status
        FROM sessions s
        JOIN users u ON u.user_id = s.user_id
        WHERE s.id = ?
        """,
        (row["session_id"],),
    ).fetchone()

    if session is None or session["state"] != "active":
        raise RefreshTokenError("no_session")

    if session["status"] != "active":
        raise RefreshTokenError("disabled")

    # Сначала обязательно проверяем Proof.
    # До этой проверки нельзя отзывать сессию из-за повторного токена.
    try:
        verify_and_consume_proof(
            conn=conn,
            public_key=session["proof_public_key"],
            proof=proof,
            expected_session_id=row["session_id"],
            expected_operation="refresh_rotation",
            now=rotated_at,
        )
    except ProofError:
        raise RefreshTokenError("invalid_proof") from None

    # Только владелец Proof Key может вызвать обработку повторного токена.
    if row["state"] in ("used", "discarded"):
        _revoke_family(
            conn,
            store,
            row["session_id"],
            rotated_at,
            "refresh_reuse",
            row["id"],
            "refresh_reuse",
        )
        raise RefreshTokenError("replay")

    if row["state"] != "current":
        raise RefreshTokenError("not_current")

    if row["expires_at"] <= rotated_at or session["expires_at"] <= rotated_at:
        conn.execute(
            """
            UPDATE sessions SET state = 'expired'
            WHERE id = ? AND state = 'active'
            """,
            (row["session_id"],),
        )
        conn.commit()
        raise RefreshTokenError("expired")

    try:
        stored = load_refresh_secret(store, row["id"])
    except SecretStoreError:
        raise RefreshTokenError("storage") from None

    if stored is None or not hashes_match(stored, refresh_token):
        _revoke_family(
            conn,
            store,
            row["session_id"],
            rotated_at,
            "storage_inconsistency",
            row["id"],
            "refresh_storage",
        )
        raise RefreshTokenError("storage")

    new_id = str(uuid.uuid4())
    new_raw = generate_refresh_token()
    new_hash = hash_refresh_token(new_raw)
    new_expires = rotated_at + REFRESH_TTL_SECONDS

    conn.execute(
        """
        INSERT INTO refresh_tokens (
            id, session_id, parent_id, token_hash,
            issued_at, expires_at, state
        ) VALUES (?, ?, ?, ?, ?, ?, 'staged')
        """,
        (
            new_id,
            row["session_id"],
            row["id"],
            new_hash,
            rotated_at,
            new_expires,
        ),
    )
    conn.commit()

    try:
        save_refresh_secret(store, new_id, new_raw)
        confirmed = load_refresh_secret(store, new_id)
    except SecretStoreError:
        _abandon(conn, store, new_id)
        raise RefreshTokenError("storage") from None

    if confirmed is None or not hashes_match(confirmed, new_raw):
        _abandon(conn, store, new_id)
        raise RefreshTokenError("storage")

    try:
        _begin_immediate(conn)

        consumed = conn.execute(
            """
            UPDATE refresh_tokens
            SET state = 'used', used_at = ?, replaced_by = ?
            WHERE id = ? AND state = 'current'
            """,
            (rotated_at, new_id, row["id"]),
        )

        if consumed.rowcount != 1:
            conn.rollback()
            _lost_race(conn, store, row["id"], new_id, rotated_at)

        promoted = conn.execute(
            """
            UPDATE refresh_tokens
            SET state = 'current'
            WHERE id = ? AND state = 'staged'
            """,
            (new_id,),
        )

        if promoted.rowcount != 1:
            conn.rollback()
            _abandon(conn, store, new_id)
            raise RefreshTokenError("storage")

        extended = conn.execute(
            """
            UPDATE sessions
            SET last_refreshed_at = ?, expires_at = ?
            WHERE id = ? AND state = 'active'
            """,
            (rotated_at, new_expires, row["session_id"]),
        )

        if extended.rowcount != 1:
            conn.rollback()
            _abandon(conn, store, new_id)
            raise RefreshTokenError("no_session")

        _event(
            conn,
            rotated_at,
            "refresh_rotated",
            "success",
            session["user_id"],
            row["session_id"],
            new_id,
        )

        conn.commit()

    except sqlite3.OperationalError:
        conn.rollback()
        _abandon(conn, store, new_id)
        raise RefreshTokenError("storage") from None

    try:
        delete_refresh_secret(store, row["id"])
    except SecretStoreError:
        pass

    access_token = issue_access_token(
        session["user_id"],
        row["session_id"],
        signing_key,
        now=rotated_at,
    )

    return {
        "session_id": row["session_id"],
        "user_id": session["user_id"],
        "token_id": new_id,
        "replaced_token_id": row["id"],
        "refresh_token": new_raw,
        "access_token": access_token,
        "access_expires_at": rotated_at + ACCESS_TTL_SECONDS,
        "refresh_expires_at": new_expires,
    }

def _lost_race(
    conn: sqlite3.Connection,
    store: SecretStore,
    old_id: str,
    new_id: str,
    now: int,
) -> None:
    """Второе обновление того же токена не создаёт ещё одну действующую пару."""
    current = conn.execute(
        "SELECT session_id, state FROM refresh_tokens WHERE id = ?",
        (old_id,),
    ).fetchone()
    if current is not None and current["state"] in ("used", "discarded"):
        _revoke_family(
            conn, store, current["session_id"], now,
            "refresh_reuse", old_id, "refresh_reuse",
        )
        raise RefreshTokenError("replay")
    _abandon(conn, store, new_id)
    raise RefreshTokenError("not_current")


def _revoke_family(
    conn: sqlite3.Connection,
    store: SecretStore,
    session_id: str,
    now: int,
    reason: str,
    token_id: str,
    event_type: str,
) -> None:
    """Закрывает одну сессию и её несданные токены. Строки used остаются used."""
    user = conn.execute(
        "SELECT user_id FROM sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    _begin_immediate(conn)
    if event_type == "refresh_reuse":
        conn.execute(
            """
            UPDATE refresh_tokens
            SET reuse_detected_at = ?
            WHERE id = ? AND reuse_detected_at IS NULL
            """,
            (now, token_id),
        )
    conn.execute(
        """
        UPDATE sessions
        SET state = 'revoked', revoked_at = ?, revoke_reason = ?
        WHERE id = ? AND state = 'active'
        """,
        (now, reason, session_id),
    )
    conn.execute(
        """
        UPDATE refresh_tokens
        SET state = 'revoked'
        WHERE session_id = ? AND state IN ('current', 'staged')
        """,
        (session_id,),
    )
    _event(
        conn,
        now,
        event_type,
        "rejected",
        None if user is None else user["user_id"],
        session_id,
        token_id,
    )
    conn.commit()
    secret_rows = conn.execute(
        "SELECT id FROM refresh_tokens WHERE session_id = ?",
        (session_id,),
    ).fetchall()
    for secret_row in secret_rows:
        try:
            delete_refresh_secret(store, secret_row["id"])
        except SecretStoreError:
            continue


def _begin_immediate(conn: sqlite3.Connection) -> None:
    """Берёт блокировку записи. Второе такое обновление ждёт первое."""
    if conn.in_transaction:
        conn.commit()
    conn.execute("BEGIN IMMEDIATE")


def _event(
    conn: sqlite3.Connection,
    now: int,
    event_type: str,
    result: str,
    user_id: str | None,
    session_id: str | None,
    token_id: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO security_events (
            created_at, event_type, result, user_id, session_id, token_id, detail
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (now, event_type, result, user_id, session_id, token_id, event_type),
    )


def recover_abandoned_tokens(conn: sqlite3.Connection, store: SecretStore) -> int:
    """
    Убирает черновики, которые не стали действующими.

    Черновик не повышается до current: действующим остаётся прежний токен.
    Секреты уже сданных и отозванных поколений стираются из связки.
    Секрет действующего токена не удаляется.
    """
    cleaned = 0
    staged = conn.execute(
        "SELECT id FROM refresh_tokens WHERE state = 'staged'"
    ).fetchall()
    for row in staged:
        try:
            delete_refresh_secret(store, row["id"])
        except SecretStoreError:
            continue
        updated = conn.execute(
            """
            UPDATE refresh_tokens
            SET state = 'discarded'
            WHERE id = ? AND state = 'staged'
            """,
            (row["id"],),
        )
        conn.commit()
        cleaned += updated.rowcount
    leftovers = conn.execute(
        """
        SELECT id FROM refresh_tokens
        WHERE state IN ('used', 'discarded', 'revoked')
        """
    ).fetchall()
    for row in leftovers:
        try:
            delete_refresh_secret(store, row["id"])
        except SecretStoreError:
            continue
    return cleaned


def _require_active_session(conn: sqlite3.Connection, session_id: str) -> None:
    """Сессия ещё только создаётся (pending) или уже активна. Отозванная не годится."""
    if not isinstance(session_id, str) or session_id.strip() == "":
        raise RefreshTokenError("no_session")
    row = conn.execute(
        "SELECT state FROM sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    if row is None or row["state"] not in ("active", "pending"):
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
