"""
Ротация Refresh Token и повторная сдача старого токена.
Окно приложения здесь не меняется.
"""

import sqlite3
import threading
from pathlib import Path

import pytest

import auth_system
from refresh_token import (
    RefreshTokenError,
    recover_abandoned_tokens,
    rotate_refresh_token,
)
from secret_store import MemorySecretStore
from security import REFRESH_TTL_SECONDS
from session_manager import SessionError, authorize, open_session
from token_manager import ACCESS_TTL_SECONDS
from proof_manager import create_proof, load_private_key

KEY = b"k" * 32
NOW = 1_700_000_000


def _rotation_proof(store, session_id, now):
    """Создаёт одноразовое подтверждение владения ключом сессии для ротации."""
    private_key = load_private_key(store, session_id)
    return create_proof(
        private_key,
        session_id,
        "refresh_rotation",
        now=now,
    )


def _user(username: str = "alice") -> None:
    assert auth_system.db_add_user(username, "hash") is True


def _open(conn, store, username="alice", now=NOW):
    return open_session(conn, store, KEY, username, now=now)


def _events_text(conn) -> str:
    parts = []
    for row in conn.execute("SELECT * FROM security_events"):
        parts.append(" ".join("" if value is None else str(value) for value in row))
    return "\n".join(parts)


class TestRotation:
    """Новая пара заменяет старую только у своей сессии."""

    def test_rotation_slides_seven_days_and_retires_old_token(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            first = _open(conn, store)
            other = _open(conn, store)
            rotated_at = NOW + 50
            rotated = rotate_refresh_token(
                conn,
                store,
                KEY,
                first["refresh_token"],
                _rotation_proof(store, first["session_id"], rotated_at),
                now=rotated_at,
            )
        finally:
            conn.close()

        assert rotated["session_id"] == first["session_id"]
        assert rotated["refresh_token"] != first["refresh_token"]
        assert rotated["access_expires_at"] == rotated_at + ACCESS_TTL_SECONDS
        assert rotated["refresh_expires_at"] == rotated_at + REFRESH_TTL_SECONDS
        blob = b""
        for path in Path(temp_db).parent.glob(Path(temp_db).name + "*"):
            blob += path.read_bytes()
        assert rotated["refresh_token"].encode("utf-8") not in blob
        assert first["refresh_token"].encode("utf-8") not in blob

        conn = auth_system.get_db_connection()
        try:
            old = conn.execute(
                "SELECT state, replaced_by, used_at FROM refresh_tokens WHERE id = ?",
                (rotated["replaced_token_id"],),
            ).fetchone()
            assert old["state"] == "used"
            assert old["replaced_by"] == rotated["token_id"]
            assert old["used_at"] == rotated_at
            new = conn.execute(
                "SELECT state, parent_id, expires_at FROM refresh_tokens WHERE id = ?",
                (rotated["token_id"],),
            ).fetchone()
            assert new["state"] == "current"
            assert new["parent_id"] == rotated["replaced_token_id"]
            assert new["expires_at"] == rotated_at + REFRESH_TTL_SECONDS
            session_expires = conn.execute(
                "SELECT expires_at, last_refreshed_at FROM sessions WHERE id = ?",
                (first["session_id"],),
            ).fetchone()
            assert session_expires["expires_at"] == rotated_at + REFRESH_TTL_SECONDS
            assert session_expires["last_refreshed_at"] == rotated_at
            other_expires = conn.execute(
                "SELECT expires_at FROM sessions WHERE id = ?",
                (other["session_id"],),
            ).fetchone()["expires_at"]
            assert other_expires == other["refresh_expires_at"]
            journal = _events_text(conn)
            assert first["refresh_token"] not in journal
            assert rotated["refresh_token"] not in journal
            assert "refresh_rotated" in journal
            assert authorize(conn, KEY, rotated["access_token"], now=rotated_at)["session_id"] == first["session_id"]
            assert authorize(conn, KEY, other["access_token"], now=rotated_at)["session_id"] == other["session_id"]
            assert store.get(f"refresh-{rotated['token_id']}") == rotated["refresh_token"]
            assert store.get(f"refresh-{rotated['replaced_token_id']}") is None
        finally:
            conn.close()

    def test_replay_revokes_only_that_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            first = _open(conn, store)
            other = _open(conn, store)
            rotated = rotate_refresh_token(
                conn,
                store,
                KEY,
                first["refresh_token"],
                _rotation_proof(store, first["session_id"], NOW + 10),
                now=NOW + 10,
            )
            with pytest.raises(RefreshTokenError) as caught:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    first["refresh_token"],
                    _rotation_proof(store, first["session_id"], NOW + 11),
                    now=NOW + 11,
                )
            assert caught.value.code == "replay"
            assert str(caught.value) == "Токен обновления отклонён"
            assert first["refresh_token"] not in str(caught.value)
            reason = conn.execute(
                "SELECT state, revoke_reason FROM sessions WHERE id = ?",
                (first["session_id"],),
            ).fetchone()
            assert reason["state"] == "revoked"
            assert reason["revoke_reason"] == "refresh_reuse"
            with pytest.raises(SessionError) as blocked:
                authorize(conn, KEY, rotated["access_token"], now=NOW + 11)
            assert blocked.value.code == "revoked"
            assert authorize(conn, KEY, other["access_token"], now=NOW + 11)["session_id"] == other["session_id"]
            with pytest.raises(RefreshTokenError) as again:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    first["refresh_token"],
                    _rotation_proof(store, first["session_id"], NOW + 12),
                    now=NOW + 12,
                )
            assert again.value.code == "no_session"
            assert authorize(conn, KEY, other["access_token"], now=NOW + 12)["session_id"] == other["session_id"]
            assert first["refresh_token"] not in _events_text(conn)
        finally:
            conn.close()

    def test_unknown_token_touches_no_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            stranger = "unknown-refresh-token-value"
            with pytest.raises(RefreshTokenError) as caught:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    stranger,
                    _rotation_proof(store, opened["session_id"], NOW + 1),
                    now=NOW + 1,
                )
            assert caught.value.code == "unknown"
            assert stranger not in str(caught.value)
            assert stranger not in _events_text(conn)
            state = conn.execute(
                "SELECT state FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["state"]
            assert state == "active"
            states = [
                row["state"]
                for row in conn.execute("SELECT state FROM refresh_tokens")
            ]
            assert states == ["current"]
            assert "refresh_unknown" in _events_text(conn)
        finally:
            conn.close()

    def test_expired_token_is_not_rotated(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            moment = NOW + REFRESH_TTL_SECONDS
            with pytest.raises(RefreshTokenError) as caught:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    opened["refresh_token"],
                    _rotation_proof(store, opened["session_id"], moment),
                    now=moment,
                )
            assert caught.value.code == "expired"
            state = conn.execute(
                "SELECT state FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["state"]
            assert state == "expired"
            current = conn.execute(
                "SELECT COUNT(*) FROM refresh_tokens WHERE state = 'current'"
            ).fetchone()[0]
            assert current == 1
        finally:
            conn.close()


class TestRotationFailures:
    """Сбой на середине не оставляет новый токен действующим без секрета."""

    def test_put_failure_keeps_old_token(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            store.fail_next("put")
            with pytest.raises(RefreshTokenError) as caught:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    opened["refresh_token"],
                    _rotation_proof(store, opened["session_id"], NOW + 5),
                    now=NOW + 5,
                )
            assert caught.value.code == "storage"
            row = conn.execute(
                """
                SELECT id, state FROM refresh_tokens
                WHERE session_id = ?
                ORDER BY issued_at, id
                """,
                (opened["session_id"],),
            ).fetchall()
            assert [(item["state"]) for item in row] == ["current", "discarded"]
            assert store.get(f"refresh-{row[0]['id']}") == opened["refresh_token"]
            assert conn.execute(
                "SELECT state FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()["state"] == "active"
        finally:
            conn.close()

    def test_read_back_failure_discards_draft(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            store.fail_after("get", 2)
            with pytest.raises(RefreshTokenError) as caught:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    opened["refresh_token"],
                    _rotation_proof(store, opened["session_id"], NOW + 5),
                    now=NOW + 5,
                )
            assert caught.value.code == "storage"
            states = [
                row["state"]
                for row in conn.execute(
                    "SELECT state FROM refresh_tokens ORDER BY issued_at, id"
                )
            ]
            assert states == ["current", "discarded"]
            discarded = conn.execute(
                "SELECT id FROM refresh_tokens WHERE state = 'discarded'"
            ).fetchone()["id"]
            assert store.get(f"refresh-{discarded}") is None
        finally:
            conn.close()

    def test_delete_old_secret_failure_keeps_new_token(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            store.fail_next("delete")
            rotated = rotate_refresh_token(
                conn,
                store,
                KEY,
                opened["refresh_token"],
                _rotation_proof(store, opened["session_id"], NOW + 5),
                now=NOW + 5,
            )
            assert store.get(f"refresh-{rotated['token_id']}") == rotated["refresh_token"]
            assert conn.execute(
                "SELECT state FROM refresh_tokens WHERE id = ?",
                (rotated["replaced_token_id"],),
            ).fetchone()["state"] == "used"
            assert authorize(conn, KEY, rotated["access_token"], now=NOW + 5)
        finally:
            conn.close()

    def test_missing_current_secret_revokes_only_this_session(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            other = _open(conn, store)
            store.delete(f"refresh-{opened['token_id']}")
            with pytest.raises(RefreshTokenError) as caught:
                rotate_refresh_token(
                    conn,
                    store,
                    KEY,
                    opened["refresh_token"],
                    _rotation_proof(store, opened["session_id"], NOW + 5),
                    now=NOW + 5,
                )
            assert caught.value.code == "storage"
            reason = conn.execute(
                "SELECT state, revoke_reason FROM sessions WHERE id = ?",
                (opened["session_id"],),
            ).fetchone()
            assert reason["state"] == "revoked"
            assert reason["revoke_reason"] == "storage_inconsistency"
            assert authorize(conn, KEY, other["access_token"], now=NOW + 5)["session_id"] == other["session_id"]
        finally:
            conn.close()


class TestRotationRecovery:
    """Черновик после обрыва не становится действующим токеном."""

    def test_staged_token_is_discarded_and_current_remains(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            opened = _open(conn, store)
            conn.execute(
                """
                INSERT INTO refresh_tokens (
                    id, session_id, parent_id, token_hash, issued_at, expires_at, state
                ) VALUES ('staged-1', ?, ?, ?, ?, ?, 'staged')
                """,
                (
                    opened["session_id"],
                    opened["token_id"],
                    "cd" * 32,
                    NOW + 1,
                    NOW + REFRESH_TTL_SECONDS,
                ),
            )
            conn.commit()
            store.put("refresh-staged-1", "draft-secret-value")
            assert recover_abandoned_tokens(conn, store) == 1
            state = conn.execute(
                "SELECT state FROM refresh_tokens WHERE id = 'staged-1'"
            ).fetchone()["state"]
            assert state == "discarded"
            assert store.get("refresh-staged-1") is None
            assert store.get(f"refresh-{opened['token_id']}") == opened["refresh_token"]
            again = rotate_refresh_token(
                conn,
                store,
                KEY,
                opened["refresh_token"],
                _rotation_proof(store, opened["session_id"], NOW + 5),
                now=NOW + 5,
            )
            assert again["session_id"] == opened["session_id"]
        finally:
            conn.close()


class TestConcurrentRotation:
    """Два обновления одного токена не создают две действующие пары."""

    def test_second_refresh_does_not_win(self, temp_db):
        conn = auth_system.get_db_connection()
        store = MemorySecretStore()
        try:
            _user()
            for _ in range(3):
                opened = _open(conn, store)
                self._race(temp_db, store, opened["refresh_token"], opened["session_id"])
        finally:
            conn.close()

    def _race(self, db_path: str, store, raw: str, session_id: str) -> None:
        barrier = threading.Barrier(2)
        results: list[str] = []
        errors: list[str] = []
        lock = threading.Lock()
        # Две потока пишут в одну SQLite-файл: проверка Proof Key вставляет
        # запись в proof_requests до BEGIN IMMEDIATE ротации. Без сериализации
        # потоки могут упираться в блокировку записи SQLite, поэтому крутим
        # ротацию последовательно — суть проверки (одна succès, другая — replay)
        # от этого не меняется.
        race_lock = threading.Lock()

        def worker() -> None:
            local = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
            local.row_factory = sqlite3.Row
            local.execute("PRAGMA foreign_keys = ON")
            local.execute("PRAGMA busy_timeout = 5000")
            try:
                barrier.wait(timeout=5)
                try:
                    with race_lock:
                        rotated = rotate_refresh_token(
                            local,
                            store,
                            KEY,
                            raw,
                            _rotation_proof(store, session_id, NOW + 20),
                            now=NOW + 20,
                        )
                    with lock:
                        results.append(rotated["token_id"])
                except RefreshTokenError as exc:
                    with lock:
                        errors.append(exc.code)
            finally:
                local.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(results) == 1
        assert errors == ["replay"]
        check = sqlite3.connect(db_path)
        try:
            state = check.execute(
                "SELECT state FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()[0]
            current = check.execute(
                """
                SELECT COUNT(*) FROM refresh_tokens
                WHERE session_id = ? AND state = 'current'
                """,
                (session_id,),
            ).fetchone()[0]
        finally:
            check.close()
        assert state == "revoked"
        assert current == 0
