"""
Независимые сессии: второй вход не закрывает первый, отзыв одной
не гасит остальные. Ротации Refresh Token здесь нет.
"""

from pathlib import Path

import pytest

import auth_system
from secret_store import MemorySecretStore
from security import REFRESH_TTL_SECONDS
from session_manager import (
    SessionError,
    authorize,
    list_sessions,
    open_session,
    recover_pending_sessions,
    refresh_session_token,
    revoke_all_sessions,
    revoke_session,
)
from token_manager import ACCESS_TTL_SECONDS, verify_access_token

KEY = b"k" * 32
NOW = 1_700_000_000


def _user(username: str = "alice") -> None:
    assert auth_system.db_add_user(username, "hash") is True


def _open(conn, store, username="alice", now=NOW):
    return open_session(conn, store, KEY, username, now=now)


class TestOpenSession:
    """Каждый вызов создаёт свою сессию и свой пропуск."""

    def test_login_alone_creates_no_session(self, temp_db):
        password = "Password123Aa"
        assert auth_system.db_add_user("alice", auth_system.hash_password(password))
        ok, _ = auth_system.login_user("alice", password)
        assert ok is True
        conn = auth_system.get_db_connection()
        try:
            assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        finally:
            conn.close()

    def test_open_keeps_refresh_secret_out_of_sqlite(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
        finally:
            conn.close()
        raw = opened["refresh_token"]
        blob = b""
        for path in Path(temp_db).parent.glob(Path(temp_db).name + "*"):
            blob += path.read_bytes()
        assert raw.encode("utf-8") not in blob
        claims = verify_access_token(opened["access_token"], KEY, now=NOW)
        assert claims["sid"] == opened["session_id"]
        assert claims["sub"] == opened["user_id"]
        assert opened["access_expires_at"] == NOW + ACCESS_TTL_SECONDS
        assert opened["refresh_expires_at"] == NOW + REFRESH_TTL_SECONDS

    def test_second_open_keeps_the_first_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            first = _open(conn, store)
            second = _open(conn, store)
            assert first["session_id"] != second["session_id"]
            assert first["refresh_token"] != second["refresh_token"]
            listed = list_sessions(conn, first["user_id"], now=NOW)
            assert {item["session_id"] for item in listed} == {
                first["session_id"],
                second["session_id"],
            }
            assert "refresh_token" not in listed[0]
            assert authorize(conn, KEY, first["access_token"], now=NOW)["session_id"] == first["session_id"]
            assert authorize(conn, KEY, second["access_token"], now=NOW)["session_id"] == second["session_id"]
        finally:
            conn.close()

    def test_unknown_and_disabled_user(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            with pytest.raises(SessionError) as missing:
                _open(conn, store)
            assert missing.value.code == "no_user"
            _user()
            conn.execute("UPDATE users SET status = 'disabled' WHERE username = 'alice'")
            conn.commit()
            with pytest.raises(SessionError) as disabled:
                _open(conn, store)
            assert disabled.value.code == "disabled"
            assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        finally:
            conn.close()

    def test_store_failure_does_not_leave_active_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        store.fail_next("put")
        try:
            _user()
            with pytest.raises(SessionError) as caught:
                _open(conn, store)
            assert caught.value.code == "storage"
            assert str(caught.value) == "Сессия отклонена"
            states = [
                row["state"]
                for row in conn.execute("SELECT state FROM sessions")
            ]
            assert states == ["revoked"]
            current = conn.execute(
                "SELECT COUNT(*) FROM refresh_tokens WHERE state = 'current'"
            ).fetchone()[0]
            assert current == 0
        finally:
            conn.close()


class TestRevokeAndAuthorize:
    """Отзыв виден следующей проверке, даже если JWT ещё не истёк."""

    def test_revoke_one_leaves_the_other(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            first = _open(conn, store)
            second = _open(conn, store)
            revoke_session(conn, store, first["session_id"], "logout", now=NOW)
            assert verify_access_token(first["access_token"], KEY, now=NOW)["sid"] == first["session_id"]
            with pytest.raises(SessionError) as caught:
                authorize(conn, KEY, first["access_token"], now=NOW)
            assert caught.value.code == "revoked"
            assert first["access_token"] not in str(caught.value)
            assert authorize(conn, KEY, second["access_token"], now=NOW)["session_id"] == second["session_id"]
            with pytest.raises(SessionError) as refresh_error:
                refresh_session_token(conn, store, first["refresh_token"], now=NOW)
            assert refresh_error.value.code == "not_current"
            assert refresh_session_token(conn, store, second["refresh_token"], now=NOW)["session_id"] == second["session_id"]
        finally:
            conn.close()

    def test_revoke_all_stops_at_this_user(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user("alice")
            _user("bob")
            alice = _open(conn, store, "alice")
            bob = _open(conn, store, "bob")
            revoke_all_sessions(conn, store, alice["user_id"], now=NOW)
            with pytest.raises(SessionError):
                authorize(conn, KEY, alice["access_token"], now=NOW)
            assert authorize(conn, KEY, bob["access_token"], now=NOW)["session_id"] == bob["session_id"]
        finally:
            conn.close()

    def test_authorize_does_not_extend_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            before = conn.execute(
                "SELECT expires_at FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["expires_at"]
            authorize(conn, KEY, opened["access_token"], now=NOW + 10)
            after = conn.execute(
                "SELECT expires_at FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["expires_at"]
            assert after == before
        finally:
            conn.close()

    def test_expired_session_rejects_live_access_token(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            conn.execute(
                "UPDATE sessions SET expires_at = ? WHERE id = ?",
                (NOW, opened["session_id"]),
            )
            conn.commit()
            with pytest.raises(SessionError) as caught:
                authorize(conn, KEY, opened["access_token"], now=NOW)
            assert caught.value.code == "expired"
            state = conn.execute(
                "SELECT state FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["state"]
            assert state == "expired"
            assert list_sessions(conn, opened["user_id"], now=NOW) == []
        finally:
            conn.close()

    def test_disabled_user_blocks_existing_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            conn.execute(
                "UPDATE users SET status = 'disabled' WHERE user_id = ?",
                (opened["user_id"],),
            )
            conn.commit()
            with pytest.raises(SessionError) as caught:
                authorize(conn, KEY, opened["access_token"], now=NOW)
            assert caught.value.code == "disabled"
        finally:
            conn.close()

    def test_delete_failure_still_revokes(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            store.fail_next("delete")
            revoke_session(conn, store, opened["session_id"], "logout", now=NOW)
            state = conn.execute(
                "SELECT state FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["state"]
            assert state == "revoked"
        finally:
            conn.close()


class TestPendingRecovery:
    """Оборванный вход не становится активной сессией и не трогает чужие."""

    def test_recover_drops_pending_only(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            user_id = opened["user_id"]
            conn.execute(
                """
                INSERT INTO sessions (id, user_id, created_at, expires_at, state)
                VALUES ('pending-1', ?, ?, ?, 'pending')
                """,
                (user_id, NOW, NOW + REFRESH_TTL_SECONDS),
            )
            conn.execute(
                """
                INSERT INTO refresh_tokens (
                    id, session_id, token_hash, issued_at, expires_at, state
                ) VALUES ('tok-pending', 'pending-1', ?, ?, ?, 'current')
                """,
                ("ab" * 32, NOW, NOW + REFRESH_TTL_SECONDS),
            )
            conn.commit()
            store.put("refresh-tok-pending", "leftover-secret")
            assert recover_pending_sessions(conn, store, now=NOW) == 1
            pending = conn.execute(
                "SELECT state, revoke_reason FROM sessions WHERE id = 'pending-1'"
            ).fetchone()
            assert pending["state"] == "revoked"
            assert pending["revoke_reason"] == "abandoned_pending"
            token_state = conn.execute(
                "SELECT state FROM refresh_tokens WHERE id = 'tok-pending'"
            ).fetchone()["state"]
            assert token_state == "revoked"
            assert store.get("refresh-tok-pending") is None
            assert authorize(conn, KEY, opened["access_token"], now=NOW)["session_id"] == opened["session_id"]
        finally:
            conn.close()
