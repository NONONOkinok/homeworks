
"""
Proof Key: создание ключей и одноразовые доказательства владения.

Для каждой сессии создаётся отдельная пара Ed25519.
Закрытый ключ хранится в системном keyring.
Открытый ключ сохраняется в SQLite.

Это собственный механизм Proof of Possession проекта,
а не полноценная реализация DPoP по RFC 9449.
"""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from secret_store import SecretStore, SecretStoreError


# Версия формата доказательства.
PROOF_VERSION = 1

# Доказательство действительно 60 секунд.
PROOF_TTL_SECONDS = 60

# Допустимое расхождение часов.
CLOCK_SKEW_SECONDS = 30

# Разрешённые операции.
ALLOWED_OPERATIONS = {
    "access_refresh",
    "refresh_rotation",
}


class ProofError(Exception):
    """Ошибка создания или проверки Proof Key."""

    def __init__(self, code: str):
        self.code = code
        super().__init__("Доказательство владения отклонено")


def _validate_session_id(session_id: str) -> None:
    """Проверяет идентификатор сессии."""

    if not isinstance(session_id, str):
        raise ValueError("Некорректный идентификатор сессии")

    if not session_id or len(session_id) > 80:
        raise ValueError("Некорректный идентификатор сессии")

    if not all(c.isalnum() or c in "-_" for c in session_id):
        raise ValueError("Некорректный идентификатор сессии")


def proof_secret_name(session_id: str) -> str:
    """Формирует имя секрета в keyring для конкретной сессии."""

    _validate_session_id(session_id)

    return f"proof-{session_id}"


def create_proof_keypair(
    store: SecretStore,
    session_id: str,
) -> dict:
    """
    Создаёт индивидуальную пару Ed25519 для сессии.

    Закрытый ключ сохраняется в keyring.
    Открытый ключ возвращается для сохранения в SQLite.
    """

    name = proof_secret_name(session_id)

    try:
        # Не допускаем случайную замену уже существующего ключа.
        if store.get(name) is not None:
            raise ProofError("key_exists")

        private_key = Ed25519PrivateKey.generate()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        encoded_private = _encode(private_bytes)

        # Сохраняем закрытый ключ.
        store.put(name, encoded_private)

        # Проверяем, что ключ действительно сохранился.
        confirmed = store.get(name)

    except SecretStoreError:
        raise ProofError("storage") from None

    if confirmed != encoded_private:
        try:
            store.delete(name)
        except SecretStoreError:
            pass

        raise ProofError("storage")

    return {
        "key_id": str(uuid.uuid4()),
        "public_key": _encode(public_bytes),
    }


def load_private_key(
    store: SecretStore,
    session_id: str,
) -> Ed25519PrivateKey:
    """Загружает закрытый ключ конкретной сессии."""

    try:
        encoded = store.get(proof_secret_name(session_id))

    except SecretStoreError:
        raise ProofError("storage") from None

    if encoded is None:
        raise ProofError("key_missing")

    try:
        private_bytes = _decode(encoded)

        return Ed25519PrivateKey.from_private_bytes(
            private_bytes
        )

    except (ValueError, TypeError, binascii.Error):
        raise ProofError("key_invalid") from None


def delete_proof_key(
    store: SecretStore,
    session_id: str,
) -> None:
    """Удаляет закрытый ключ отозванной сессии."""

    try:
        store.delete(proof_secret_name(session_id))

    except SecretStoreError:
        raise ProofError("storage") from None


def create_proof(
    private_key: Ed25519PrivateKey,
    session_id: str,
    operation: str,
    request_id: str | None = None,
    now: int | None = None,
) -> str:
    """
    Создаёт подписанное доказательство владения закрытым ключом.

    В доказательство входят:
    sid — идентификатор сессии;
    op — назначение операции;
    rid — идентификатор запроса;
    jti — уникальный идентификатор доказательства;
    iat — время создания.
    """

    _validate_session_id(session_id)

    if operation not in ALLOWED_OPERATIONS:
        raise ValueError("Недопустимая операция")

    if request_id is None:
        request_id = str(uuid.uuid4())

    if (
        not isinstance(request_id, str)
        or not request_id
        or len(request_id) > 128
    ):
        raise ValueError("Некорректный идентификатор запроса")

    issued_at = _clock(now)

    claims = {
        "v": PROOF_VERSION,
        "sid": session_id,
        "op": operation,
        "rid": request_id,
        "jti": str(uuid.uuid4()),
        "iat": issued_at,
    }

    # Каноническое представление JSON.
    body = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    # Подписываем данные закрытым ключом.
    signature = private_key.sign(body)

    # Формат: данные.подпись
    return f"{_encode(body)}.{_encode(signature)}"


def verify_and_consume_proof(
    conn: sqlite3.Connection,
    public_key: str,
    proof: str,
    expected_session_id: str,
    expected_operation: str,
    now: int | None = None,
) -> dict:
    """
    Проверяет доказательство и регистрирует его использование.

    Повторное предъявление одного jti отклоняется.
    Запись выполняется внутри SAVEPOINT, поэтому функцию
    можно использовать внутри внешней транзакции.
    """

    _validate_session_id(expected_session_id)

    if expected_operation not in ALLOWED_OPERATIONS:
        raise ValueError("Недопустимая операция")

    checked_at = _clock(now)

    if (
        not isinstance(proof, str)
        or proof.count(".") != 1
        or len(proof) > 4096
    ):
        raise ProofError("malformed")

    try:
        body_part, signature_part = proof.split(".")

        body = _decode(body_part)
        signature = _decode(signature_part)

        claims = json.loads(body.decode("utf-8"))

        public_bytes = _decode(public_key)

        key = Ed25519PublicKey.from_public_bytes(public_bytes)

        # Проверяем криптографическую подпись.
        key.verify(signature, body)

    except (
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        InvalidSignature,
        binascii.Error,
    ):
        raise ProofError("bad_signature") from None

    required_fields = {
        "v",
        "sid",
        "op",
        "rid",
        "jti",
        "iat",
    }

    if not isinstance(claims, dict):
        raise ProofError("claims")

    if set(claims) != required_fields:
        raise ProofError("claims")

    if (
        isinstance(claims["v"], bool)
        or claims["v"] != PROOF_VERSION
    ):
        raise ProofError("claims")

    if claims["sid"] != expected_session_id:
        raise ProofError("wrong_session")

    if claims["op"] != expected_operation:
        raise ProofError("wrong_operation")

    for field in ("rid", "jti"):
        value = claims[field]

        if (
            not isinstance(value, str)
            or not value
            or len(value) > 128
        ):
            raise ProofError("claims")

    issued_at = claims["iat"]

    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
    ):
        raise ProofError("claims")

    if issued_at > checked_at + CLOCK_SKEW_SECONDS:
        raise ProofError("not_yet_valid")

    if checked_at - issued_at > PROOF_TTL_SECONDS:
        raise ProofError("expired")

    # Регистрируем доказательство как использованное.
    # Уникальность (session_id, jti) защищает от повторного предъявления.
    conn.execute("SAVEPOINT consume_proof")

    try:
        conn.execute(
            """
            INSERT INTO proof_requests (
                session_id,
                jti,
                request_id,
                operation,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                expected_session_id,
                claims["jti"],
                claims["rid"],
                expected_operation,
                checked_at,
            ),
        )

        conn.execute("RELEASE SAVEPOINT consume_proof")

    except sqlite3.IntegrityError:
        conn.execute("ROLLBACK TO SAVEPOINT consume_proof")
        conn.execute("RELEASE SAVEPOINT consume_proof")

        raise ProofError("replay") from None

    return claims


def cleanup_expired_proofs(
    conn: sqlite3.Connection,
    now: int | None = None,
) -> int:
    """
    Удаляет доказательства, которые уже не могут быть приняты.

    Возвращает количество удалённых записей.
    """

    checked_at = _clock(now)

    cutoff = (
        checked_at
        - PROOF_TTL_SECONDS
        - CLOCK_SKEW_SECONDS
    )

    cursor = conn.execute(
        """
        DELETE FROM proof_requests
        WHERE created_at < ?
        """,
        (cutoff,),
    )

    return cursor.rowcount


def _encode(value: bytes) -> str:
    """Кодирование Base64 URL-safe без символов дополнения."""

    return (
        base64.urlsafe_b64encode(value)
        .rstrip(b"=")
        .decode("ascii")
    )


def _decode(value: str) -> bytes:
    """Строгое декодирование Base64 URL-safe."""

    if not isinstance(value, str):
        raise ValueError("Некорректные данные")

    encoded = value.encode("ascii")

    encoded += b"=" * (-len(encoded) % 4)

    return base64.b64decode(
        encoded,
        altchars=b"-_",
        validate=True,
    )


def _clock(now: int | None) -> int:
    """Возвращает текущее время в Unix-секундах."""

    if now is None:
        return int(time.time())

    if (
        isinstance(now, bool)
        or not isinstance(now, int)
        or now < 0
    ):
        raise ValueError("Некорректное время")

    return now
