"""
Миграции SQLite.

Существующая таблица users сохраняется. У старых строк остаются логин,
хеш пароля и дата создания. Рядом появляется постоянный user_id: он нужен
сессиям и JWT и не меняется, даже если когда-нибудь изменится логин.

Новые таблицы на этом шаге только создаются. Записывать в них сессии
будет следующий этап.
"""

import uuid
from datetime import datetime, timezone

# Номера миграций. Каждая применяется один раз.
_BASELINE = 1
_USERS_IDENTITY = 2
_SESSION_TABLES = 3
_PROOF_KEY_TABLES = 4


def migrate(conn) -> None:
    """Приводит открытую базу к текущей схеме. Повторный вызов ничего не меняет."""
    _ensure_migration_table(conn)
    applied = _applied_versions(conn)

    if _BASELINE not in applied:
        _migrate_baseline(conn)
        _mark(conn, _BASELINE)

    if _USERS_IDENTITY not in applied:
        _migrate_user_identity(conn)
        _mark(conn, _USERS_IDENTITY)

    if _SESSION_TABLES not in applied:
        _migrate_session_tables(conn)
        _mark(conn, _SESSION_TABLES)

    if _SESSION_TABLES not in applied:
        _migrate_session_tables(conn)
        _mark(conn, _SESSION_TABLES)


def _ensure_migration_table(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )


def _applied_versions(conn) -> set[int]:
    return {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}


def _mark(conn, version: int) -> None:
    conn.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        (version, datetime.now(timezone.utc).isoformat()),
    )


def _migrate_baseline(conn) -> None:
    """Старая таблица пользователей. На уже заполненной базе ничего не стирает."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def _column_names(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_user_identity(conn) -> None:
    """
    Добавляет user_id и status.

    SQLite не даёт просто дописать столбец NOT NULL без значения по умолчанию,
    а user_id у каждой строки свой. Поэтому старая таблица копируется в новую
    внутри той же транзакции: при сбое откат вернёт прежнюю users целиком.
    """
    if "user_id" in _column_names(conn, "users"):
        return

    conn.execute(
        """
        CREATE TABLE users_new (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'disabled'))
        )
        """
    )
    rows = conn.execute(
        "SELECT username, password_hash, created_at FROM users"
    ).fetchall()
    for row in rows:
        conn.execute(
            """
            INSERT INTO users_new (username, password_hash, created_at, user_id, status)
            VALUES (?, ?, ?, ?, 'active')
            """,
            (row[0], row[1], row[2], str(uuid.uuid4())),
        )
    conn.execute("DROP TABLE users")
    conn.execute("ALTER TABLE users_new RENAME TO users")


def _migrate_session_tables(conn) -> None:
    """Таблицы сессий, истории Refresh Token и журнала. Данные пользователей не трогает."""
    conn.execute(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id),
            created_at INTEGER NOT NULL,
            last_refreshed_at INTEGER,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL
                CHECK (state IN ('pending', 'active', 'expired', 'revoked')),
            revoked_at INTEGER,
            revoke_reason TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE refresh_tokens (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(id),
            parent_id TEXT REFERENCES refresh_tokens(id),
            replaced_by TEXT REFERENCES refresh_tokens(id),
            token_hash TEXT NOT NULL UNIQUE,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL
                CHECK (state IN ('staged', 'current', 'used', 'discarded', 'revoked')),
            used_at INTEGER,
            reuse_detected_at INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY,
            created_at INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            result TEXT NOT NULL,
            user_id TEXT,
            username TEXT,
            session_id TEXT,
            token_id TEXT,
            detail TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX idx_sessions_user_state ON sessions(user_id, state)"
    )
    conn.execute(
        "CREATE INDEX idx_sessions_expires ON sessions(expires_at)"
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX one_current_refresh
        ON refresh_tokens(session_id) WHERE state = 'current'
        """
    )
    conn.execute(
        "CREATE INDEX idx_refresh_session_state ON refresh_tokens(session_id, state)"
    )
    conn.execute(
        "CREATE INDEX idx_refresh_replaced_by ON refresh_tokens(replaced_by)"
    )
    conn.execute(
        "CREATE INDEX idx_events_created ON security_events(created_at)"
    )
    conn.execute(
        "CREATE INDEX idx_events_session ON security_events(session_id)"
    )

def _migrate_proof_key_tables(conn) -> None:
    """
    Добавляет данные Proof Key к существующим сессиям
    и создаёт таблицу использованных доказательств.
    """

    # Добавляем поля открытого ключа.
    columns = _column_names(conn, "sessions")

    if "proof_key_id" not in columns:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN proof_key_id TEXT"
        )

    if "proof_public_key" not in columns:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN proof_public_key TEXT"
        )

    # Один идентификатор ключа не должен принадлежать
    # нескольким сессиям.
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_sessions_proof_key
        ON sessions(proof_key_id)
        WHERE proof_key_id IS NOT NULL
        """
    )

    # История использованных Proof.
    conn.execute(
        """
        CREATE TABLE proof_requests (
            id INTEGER PRIMARY KEY,
            session_id TEXT NOT NULL
                REFERENCES sessions(id) ON DELETE CASCADE,
            jti TEXT NOT NULL,
            request_id TEXT NOT NULL,
            operation TEXT NOT NULL
                CHECK (
                    operation IN (
                        'access_refresh',
                        'refresh_rotation'
                    )
                ),
            created_at INTEGER NOT NULL,
            UNIQUE(session_id, jti)
        )
        """
    )

    conn.execute(
        """
        CREATE INDEX idx_proof_requests_created
        ON proof_requests(created_at)
        """
    )