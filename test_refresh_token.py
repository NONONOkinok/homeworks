"""
Refresh Token: случайная строка, хеш в SQLite, исходник только в хранилище.
Ротации и отзыва сессий нет.
"""

import sqlite3
from pathlib import Path

import pytest

import auth_system
from refresh_token import RefreshTokenError, issue_refresh_token, verify_refresh_token
from secret_store import MemorySecretStore, SecretStoreError
from security import REFRESH_TTL_SECONDS, generate_refresh_token, hash_refresh_token, hashes_match

NOW = 1_700_000_000


def _session(conn) -> str:
    assert auth_system.db_add_user("alice", "hash") is True
    user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?",
        ("alice",),
    ).fetchone()["user_id"]
    session_id = "session-1"
    conn.execute(
        """
        INSERT INTO sessions (id, user_id, created_at, expires_at, state)
        VALUES (?, ?, ?, ?, 'active')
        """,
        (session_id, user_id, NOW, NOW + REFRESH_TTL_SECONDS),
    )
    conn.commit()
    return session_id


def _rejected(conn, store, raw: str, code: str, now: int = NOW) -> None:
    with pytest.raises(RefreshTokenError) as caught:
        verify_refresh_token(conn, store, raw, now=now)
    assert caught.value.code == code
    assert str(caught.value) == "Токен обновления отклонён"
    if raw:
        assert raw not in str(caught.value)


class TestRefreshTokenMaterial:
    """Строка случайная, отпечаток стабильный и не равен самой строке."""

    def test_tokens_are_unique_opaque_strings(self):
        tokens = {generate_refresh_token() for _ in range(20)}
        assert len(tokens) == 20
        for token in tokens:
            assert "." not in token
            assert len(token) >= 43
            assert token != hash_refresh_token(token)

    def test_hash_is_stable_sha256(self):
        token = generate_refresh_token()
        digest = hash_refresh_token(token)
        assert digest == hash_refresh_token(token)
        assert len(digest) == 64
        assert digest != token
        assert hashes_match(digest, digest) is True
        assert hashes_match(digest, hash_refresh_token(generate_refresh_token())) is False


class TestIssueAndVerify:
    """В базе лежит хеш. Проверка принимает только действующую строку."""

    def test_database_keeps_only_the_hash(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            session_id = _session(conn)
            issued = issue_refresh_token(conn, store, session_id, now=NOW)
        finally:
            conn.close()

        raw = issued["refresh_token"]
        blob = b""
        for path in Path(temp_db).parent.glob(Path(temp_db).name + "*"):
            blob += path.read_bytes()
        assert raw.encode("utf-8") not in blob

        conn = auth_system.get_db_connection()
        try:
            row = conn.execute(
                "SELECT token_hash, state, expires_at FROM refresh_tokens"
            ).fetchone()
            assert row["token_hash"] == hash_refresh_token(raw)
            assert row["state"] == "current"
            assert row["expires_at"] == NOW + REFRESH_TTL_SECONDS
            assert row["token_hash"] != raw
        finally:
            conn.close()
        assert store.get(f"refresh-{issued['token_id']}") == raw

    def test_verify_accepts_token_until_last_second(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            issued = issue_refresh_token(conn, store, _session(conn), now=NOW)
            checked = verify_refresh_token(
                conn,
                store,
                issued["refresh_token"],
                now=NOW + REFRESH_TTL_SECONDS - 1,
            )
            assert checked["token_id"] == issued["token_id"]
            assert "refresh_token" not in checked
        finally:
            conn.close()

    def test_verify_rejects_expired_token(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            issued = issue_refresh_token(conn, store, _session(conn), now=NOW)
            _rejected(
                conn,
                store,
                issued["refresh_token"],
                "expired",
                now=NOW + REFRESH_TTL_SECONDS,
            )
        finally:
            conn.close()

    def test_unknown_token_changes_nothing(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            issued = issue_refresh_token(conn, store, _session(conn), now=NOW)
            before = conn.execute(
                "SELECT id, state FROM refresh_tokens"
            ).fetchall()
            store.fail_next("get")
            _rejected(conn, store, generate_refresh_token(), "unknown")
            after = conn.execute(
                "SELECT id, state FROM refresh_tokens"
            ).fetchall()
            assert [(row["id"], row["state"]) for row in after] == [
                (row["id"], row["state"]) for row in before
            ]
            assert after[0]["id"] == issued["token_id"]
            sessions = conn.execute("SELECT state FROM sessions").fetchall()
            assert [row["state"] for row in sessions] == ["active"]
        finally:
            conn.close()

    def test_schema_rejects_second_current_row(self, temp_db):
        conn = auth_system.get_db_connection()
        try:
            session_id = _session(conn)
            issue_refresh_token(conn, MemorySecretStore(), session_id, now=NOW)
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO refresh_tokens (
                        id, session_id, token_hash, issued_at, expires_at, state
                    ) VALUES ('other', ?, ?, ?, ?, 'current')
                    """,
                    (session_id, "ab" * 32, NOW, NOW + 1),
                )
            conn.rollback()
        finally:
            conn.close()

    def test_second_issue_is_refused(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            session_id = _session(conn)
            first = issue_refresh_token(conn, store, session_id, now=NOW)
            with pytest.raises(RefreshTokenError) as caught:
                issue_refresh_token(conn, store, session_id, now=NOW)
            assert caught.value.code == "already_issued"
            row = conn.execute(
                "SELECT id, state FROM refresh_tokens"
            ).fetchone()
            assert row["id"] == first["token_id"]
            assert row["state"] == "current"
        finally:
            conn.close()

    def test_not_current_token_is_rejected(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            issued = issue_refresh_token(conn, store, _session(conn), now=NOW)
            conn.execute(
                "UPDATE refresh_tokens SET state = 'used' WHERE id = ?",
                (issued["token_id"],),
            )
            conn.commit()
            _rejected(conn, store, issued["refresh_token"], "not_current")
            state = conn.execute("SELECT state FROM sessions").fetchone()["state"]
            assert state == "active"
        finally:
            conn.close()

    def test_missing_secret_does_not_revoke_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            issued = issue_refresh_token(conn, store, _session(conn), now=NOW)
            store.delete(f"refresh-{issued['token_id']}")
            _rejected(conn, store, issued["refresh_token"], "storage")
            assert conn.execute("SELECT state FROM sessions").fetchone()["state"] == "active"
            assert conn.execute(
                "SELECT state FROM refresh_tokens"
            ).fetchone()["state"] == "current"
        finally:
            conn.close()


class TestStoreFailures:
    """Сбой связки не оставляет действующий токен без секрета."""

    def test_put_failure_discards_draft(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        store.fail_next("put")
        try:
            with pytest.raises(SecretStoreError):
                issue_refresh_token(conn, store, _session(conn), now=NOW)
            row = conn.execute(
                "SELECT state FROM refresh_tokens"
            ).fetchone()
            assert row["state"] == "discarded"
            assert conn.execute(
                "SELECT state FROM sessions"
            ).fetchone()["state"] == "active"
        finally:
            conn.close()

    def test_read_back_failure_discards_draft(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        store.fail_next("get")
        try:
            with pytest.raises(SecretStoreError):
                issue_refresh_token(conn, store, _session(conn), now=NOW)
            row = conn.execute("SELECT id, state FROM refresh_tokens").fetchone()
            assert row["state"] == "discarded"
            assert store.get(f"refresh-{row['id']}") is None
        finally:
            conn.close()

    def test_inactive_session_stores_nothing(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            session_id = _session(conn)
            conn.execute(
                "UPDATE sessions SET state = 'revoked' WHERE id = ?",
                (session_id,),
            )
            conn.commit()
            with pytest.raises(RefreshTokenError) as caught:
                issue_refresh_token(conn, store, session_id, now=NOW)
            assert caught.value.code == "no_session"
            assert conn.execute("SELECT COUNT(*) FROM refresh_tokens").fetchone()[0] == 0
            assert store.get("jwt-hs256-key") is None
        finally:
            conn.close()
