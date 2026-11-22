"""
Независимые сессии одного пользователя.

Простыми словами. Каждый успешный вход заводит отдельную карточку сессии.
Второй вход не закрывает первую. Закрыть можно одну карточку или все карточки
этого человека. Короткий пропуск JWT сам по себе сессию не продлевает и не
оставляет её живой: перед действием карточка читается из базы заново.

Технически сессия сначала записывается как pending. Действующей она становится
только после того, как Refresh Token сохранён в хранилище и его хеш отмечен
current. Чужие сессии эта операция не меняет. Обновление токена заменяет
только пару этой сессии.
"""

from __future__ import annotations

import sqlite3
import uuid

from refresh_token import (
    RefreshTokenError,
    issue_refresh_token,
    rotate_refresh_token,
    verify_refresh_token,
)
from secret_store import SecretStore, SecretStoreError, delete_refresh_secret
from security import REFRESH_TTL_SECONDS
from token_manager import (
    ACCESS_TTL_SECONDS,
    AccessTokenError,
    issue_access_token,
    verify_access_token,
)
from proof_manager import (
    ProofError,
    create_proof_keypair,
    delete_proof_key,
    verify_and_consume_proof,
)


class SessionError(Exception):
    """Сессия отклонена. Текст не содержит токены и секреты."""

    def __init__(self, code: str):
        self.code = code
        super().__init__("Сессия отклонена")


def open_session(
    conn: sqlite3.Connection,
    store: SecretStore,
    signing_key: bytes,
    username: str,
    now: int | None = None,
) -> dict:
    """Создаёт независимую сессию с отдельной парой Proof Key."""
    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise ValueError("Секрет HS256 должен быть 32 байтами")

    opened_at = _clock(now)
    user = _user_by_name(conn, username)
    session_id = str(uuid.uuid4())

    try:
        proof_keys = create_proof_keypair(store, session_id)
    except ProofError:
        raise SessionError("proof_storage") from None

    refresh_expires_at = opened_at + REFRESH_TTL_SECONDS

    try:
        conn.execute(
            """
            INSERT INTO sessions (
                id, user_id, created_at, expires_at, state,
                proof_key_id, proof_public_key
            )
            VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                session_id,
                user["user_id"],
                opened_at,
                refresh_expires_at,
                proof_keys["key_id"],
                proof_keys["public_key"],
            ),
        )
        conn.commit()

        issued = issue_refresh_token(
            conn,
            store,
            session_id,
            now=opened_at,
        )

        activated = conn.execute(
            """
            UPDATE sessions
            SET state = 'active'
            WHERE id = ? AND state = 'pending'
            """,
            (session_id,),
        )

        if activated.rowcount != 1:
            raise SessionError("storage")

        conn.commit()

    except (RefreshTokenError, SecretStoreError, sqlite3.Error, SessionError):
        conn.rollback()
        _close_pending(conn, store, session_id, opened_at)

        try:
            delete_proof_key(store, session_id)
        except ProofError:
            pass

        raise SessionError("storage") from None

    access_token = issue_access_token(
        user["user_id"],
        session_id,
        signing_key,
        now=opened_at,
    )

    return {
        "session_id": session_id,
        "user_id": user["user_id"],
        "proof_key_id": proof_keys["key_id"],
        "proof_public_key": proof_keys["public_key"],
        "token_id": issued["token_id"],
        "access_token": access_token,
        "refresh_token": issued["refresh_token"],
        "access_expires_at": opened_at + ACCESS_TTL_SECONDS,
        "refresh_expires_at": issued["expires_at"],
    }


def authorize(
    conn: sqlite3.Connection,
    signing_key: bytes,
    access_token: str,
    now: int | None = None,
) -> dict:
    """
    Проверяет пропуск и заново читает сессию из SQLite.

    Верная подпись и ненаступивший exp не достаточны. Отозванная, истёкшая
    или чужая сессия отклоняется. Срок сессии эта проверка не продлевает.
    """
    checked_at = _clock(now)
    claims = verify_access_token(access_token, signing_key, now=checked_at)
    row = conn.execute(
        """
        SELECT s.user_id, s.state, s.expires_at, u.status
        FROM sessions s
        JOIN users u ON u.user_id = s.user_id
        WHERE s.id = ?
        """,
        (claims["sid"],),
    ).fetchone()
    if row is None or row["user_id"] != claims["sub"]:
        raise SessionError("revoked")
    if row["status"] != "active":
        raise SessionError("disabled")
    if row["state"] == "active" and row["expires_at"] <= checked_at:
        conn.execute(
            """
            UPDATE sessions
            SET state = 'expired'
            WHERE id = ? AND state = 'active'
            """,
            (claims["sid"],),
        )
        conn.commit()
        raise SessionError("expired")
    if row["state"] != "active":
        raise SessionError("revoked")
    return {
        "user_id": claims["sub"],
        "session_id": claims["sid"],
        "access_expires_at": claims["exp"],
        "session_expires_at": row["expires_at"],
    }

def refresh_access_token(
    conn: sqlite3.Connection,
    store: SecretStore,
    refresh_token: str,
    proof: str,
    signing_key: bytes,
    now: int | None = None,
) -> dict:
    """
    Обновляет только Access Token.

    Refresh Token остаётся прежним. Для операции требуется
    одноразовое доказательство владения ключом этой сессии.
    """
    checked_at = _clock(now)

    try:
        token_data = verify_refresh_token(
            conn,
            store,
            refresh_token,
            now=checked_at,
        )

        session = conn.execute(
            """
            SELECT s.user_id, s.proof_public_key, s.state, u.status
            FROM sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.id = ?
            """,
            (token_data["session_id"],),
        ).fetchone()

        if session is None or session["state"] != "active":
            raise SessionError("revoked")

        if session["status"] != "active":
            raise SessionError("disabled")

        if not session["proof_public_key"]:
            raise SessionError("proof_missing")

        verify_and_consume_proof(
            conn,
            session["proof_public_key"],
            proof,
            token_data["session_id"],
            "access_refresh",
            now=checked_at,
        )

        access_token = issue_access_token(
            session["user_id"],
            token_data["session_id"],
            signing_key,
            now=checked_at,
        )

        conn.commit()

        return {
            "session_id": token_data["session_id"],
            "user_id": session["user_id"],
            "access_token": access_token,
            "access_expires_at": checked_at + ACCESS_TTL_SECONDS,
            "refresh_token": refresh_token,
            "refresh_expires_at": token_data["expires_at"],
        }

    except ProofError as exc:
        conn.rollback()
        raise SessionError(f"proof_{exc.code}") from None

    except RefreshTokenError as exc:
        conn.rollback()
        raise SessionError(exc.code) from None

def list_sessions(
    conn: sqlite3.Connection,
    user_id: str,
    now: int | None = None,
) -> list[dict]:
    """Активные сессии пользователя. Токены и хеши в список не входят."""
    checked_at = _clock(now)
    conn.execute(
        """
        UPDATE sessions
        SET state = 'expired'
        WHERE user_id = ? AND state = 'active' AND expires_at <= ?
        """,
        (user_id, checked_at),
    )
    conn.commit()
    rows = conn.execute(
        """
        SELECT id, created_at, expires_at, state
        FROM sessions
        WHERE user_id = ? AND state = 'active'
        ORDER BY created_at, id
        """,
        (user_id,),
    ).fetchall()
    return [
        {
            "session_id": row["id"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "state": row["state"],
        }
        for row in rows
    ]


def revoke_session(
    conn: sqlite3.Connection,
    store: SecretStore,
    session_id: str,
    reason: str,
    now: int | None = None,
) -> None:
    """Закрывает одну сессию. Остальные сессии того же пользователя не трогает."""
    checked_at = _clock(now)
    row = conn.execute(
        "SELECT state FROM sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    if row is None:
        raise SessionError("no_session")
    if row["state"] == "pending":
        _close_pending(conn, store, session_id, checked_at)
        return
    if row["state"] == "active":
        conn.execute(
            """
            UPDATE sessions
            SET state = 'revoked', revoked_at = ?, revoke_reason = ?
            WHERE id = ? AND state = 'active'
            """,
            (checked_at, reason, session_id),
        )
        conn.execute(
            """
            UPDATE refresh_tokens
            SET state = 'revoked'
            WHERE session_id = ? AND state IN ('current', 'staged')
            """,
            (session_id,),
        )
        conn.commit()
    _delete_session_secrets(store, conn, session_id)


def revoke_all_sessions(
    conn: sqlite3.Connection,
    store: SecretStore,
    user_id: str,
    now: int | None = None,
) -> None:
    """Закрывает все незавершённые сессии одного пользователя."""
    rows = conn.execute(
        """
        SELECT id FROM sessions
        WHERE user_id = ? AND state IN ('active', 'pending')
        """,
        (user_id,),
    ).fetchall()
    for row in rows:
        revoke_session(conn, store, row["id"], "revoke_all", now=now)


def recover_pending_sessions(
    conn: sqlite3.Connection,
    store: SecretStore,
    now: int | None = None,
) -> int:
    """
    Снимает сессии, которые так и не стали активными.

    Незавершённый вход не превращается в действующую сессию: иначе старый
    черновик мог бы ожить после сбоя. Уже активные сессии не изменяются.
    """
    checked_at = _clock(now)
    rows = conn.execute(
        "SELECT id FROM sessions WHERE state = 'pending'"
    ).fetchall()
    closed = 0
    for row in rows:
        if _close_pending(conn, store, row["id"], checked_at):
            closed += 1
    return closed



def refresh_session_token(
    conn: sqlite3.Connection,
    store: SecretStore,
    refresh_token: str,
    proof: str,
    signing_key: bytes,
    now: int | None = None,
) -> dict:
    """Заменяет Refresh Token после проверки Proof Key."""

    try:
        return rotate_refresh_token(
            conn=conn,
            store=store,
            signing_key=signing_key,
            refresh_token=refresh_token,
            proof=proof,
            now=now,
        )
    except RefreshTokenError as exc:
        raise SessionError(exc.code) from None


def _user_by_name(conn: sqlite3.Connection, username: str) -> sqlite3.Row:
    if not isinstance(username, str) or username.strip() == "":
        raise SessionError("no_user")
    row = conn.execute(
        "SELECT user_id, status FROM users WHERE username = ?",
        (username.strip(),),
    ).fetchone()
    if row is None:
        raise SessionError("no_user")
    if row["status"] != "active":
        raise SessionError("disabled")
    return row


def _close_pending(
    conn: sqlite3.Connection,
    store: SecretStore,
    session_id: str,
    now: int,
) -> bool:
    """Убирает секрет и только потом помечает pending закрытой. False — связка не ответила."""
    token_rows = conn.execute(
        "SELECT id FROM refresh_tokens WHERE session_id = ?",
        (session_id,),
    ).fetchall()
    for token in token_rows:
        try:
            delete_refresh_secret(store, token["id"])
        except SecretStoreError:
            return False
    conn.execute(
        """
        UPDATE refresh_tokens
        SET state = 'discarded'
        WHERE session_id = ? AND state = 'staged'
        """,
        (session_id,),
    )
    conn.execute(
        """
        UPDATE refresh_tokens
        SET state = 'revoked'
        WHERE session_id = ? AND state = 'current'
        """,
        (session_id,),
    )
    conn.execute(
        """
        UPDATE sessions
        SET state = 'revoked', revoked_at = ?, revoke_reason = 'abandoned_pending'
        WHERE id = ? AND state = 'pending'
        """,
        (now, session_id),
    )
    try:
        delete_proof_key(store, session_id)
    except ProofError:
        pass
    conn.commit()
    return True


def _delete_session_secrets(
    store: SecretStore,
    conn: sqlite3.Connection,
    session_id: str,
) -> None:
    rows = conn.execute(
        "SELECT id FROM refresh_tokens WHERE session_id = ?",
        (session_id,),
    ).fetchall()
    for row in rows:
        try:
            delete_refresh_secret(store, row["id"])
        except SecretStoreError:
            continue
        try:
            delete_proof_key(store, session_id)
        except ProofError:
            pass


def _clock(now: int | None) -> int:
    if now is None:
        import time
        return int(time.time())
    if isinstance(now, bool) or not isinstance(now, int):
        raise ValueError("Время сессии должно быть целым числом секунд")
    return now
