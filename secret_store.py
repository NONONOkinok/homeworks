"""
Секреты приложения живут в системном хранилище, а не в исходниках и не в SQLite.

Простыми словами: пароль подписи пропусков и сами Refresh Token — это ключи от
сейфа. Их кладут в связку паролей Windows (keyring). В базе остаётся только
отпечаток Refresh Token. Если связка недоступна, новый секрет не выдумывается:
старые подписи иначе перестали бы совпадать, а новый секрет молча подменил бы
настоящий.

Это ещё не выпуск JWT и не ротация. Здесь только положить, прочитать и удалить
секрет.
"""

from __future__ import annotations

import re
import secrets
from typing import Protocol

SERVICE_NAME = "info-sec-auth-homework"
SIGNING_KEY_NAME = "jwt-hs256-key"
SIGNING_KEY_BYTES = 32

_NAME_RE = re.compile(r"^[0-9A-Za-z_-]{1,120}$")
_TOKEN_ID_RE = re.compile(r"^[0-9A-Za-z_-]{1,80}$")


class SecretStoreError(Exception):
    """Хранилище недоступно или уже записанный секрет нельзя принять."""


class SecretStore(Protocol):
    """Общий контракт. Тесты подставляют память, приложение — keyring."""

    def get(self, name: str) -> str | None:
        """Возвращает секрет или None, если такой записи нет."""

    def put(self, name: str, value: str) -> None:
        """Сохраняет секрет. Пустое значение не записывается."""

    def delete(self, name: str) -> None:
        """Удаляет секрет. Повторное удаление отсутствующей записи — не ошибка."""


def refresh_secret_name(token_id: str) -> str:
    """Имя записи одного поколения Refresh Token. У каждой генерации оно своё."""
    if not _TOKEN_ID_RE.fullmatch(token_id or ""):
        raise ValueError("Некорректный идентификатор токена")
    return f"refresh-{token_id}"


def save_refresh_secret(store: SecretStore, token_id: str, secret: str) -> None:
    """Кладёт исходный Refresh Token в хранилище под именем его поколения."""
    if not secret:
        raise ValueError("Пустой секрет не сохраняется")
    store.put(refresh_secret_name(token_id), secret)


def load_refresh_secret(store: SecretStore, token_id: str) -> str | None:
    """Читает Refresh Token поколения. None — записи нет, не сбой хранилища."""
    return store.get(refresh_secret_name(token_id))


def delete_refresh_secret(store: SecretStore, token_id: str) -> None:
    """Удаляет Refresh Token поколения. Если его уже нет, это нормально."""
    store.delete(refresh_secret_name(token_id))


def load_or_create_signing_key(store: SecretStore) -> bytes:
    """
    Возвращает секрет HS256 длиной 32 байта.

    Если запись уже есть, она используется как есть. Новый секрет создаётся
    только когда хранилище ответило «записи нет». Ошибка чтения не превращается
    в создание другого секрета. Повреждённая запись тоже не перезаписывается.
    """
    existing = store.get(SIGNING_KEY_NAME)
    if existing is not None:
        return _decode_signing_key(existing)

    fresh = secrets.token_bytes(SIGNING_KEY_BYTES)
    store.put(SIGNING_KEY_NAME, fresh.hex())
    confirmed = store.get(SIGNING_KEY_NAME)
    if confirmed is None:
        raise SecretStoreError("Не удалось сохранить секрет подписи")
    return _decode_signing_key(confirmed)


def _decode_signing_key(stored: str) -> bytes:
    try:
        key = bytes.fromhex(stored)
    except ValueError:
        raise SecretStoreError("Секрет подписи недоступен") from None
    if len(key) != SIGNING_KEY_BYTES:
        raise SecretStoreError("Секрет подписи недоступен")
    return key


def _validate_name(name: str) -> None:
    if not _NAME_RE.fullmatch(name or ""):
        raise ValueError("Некорректное имя секрета")


class MemorySecretStore:
    """Память процесса вместо keyring. Для тестов, не для настоящего запуска."""

    def __init__(self) -> None:
        self._items: dict[str, str] = {}
        self._failures: dict[str, int] = {"get": 0, "put": 0, "delete": 0}

    def fail_next(self, operation: str, times: int = 1) -> None:
        """Следующие вызовы операции завершаются ошибкой хранилища."""
        if operation not in self._failures:
            raise ValueError("Неизвестная операция хранилища")
        if times < 1:
            raise ValueError("Число сбоев должно быть положительным")
        self._failures[operation] += times

    def get(self, name: str) -> str | None:
        _validate_name(name)
        self._use("get")
        return self._items.get(name)

    def put(self, name: str, value: str) -> None:
        _validate_name(name)
        if value == "":
            raise ValueError("Пустой секрет не сохраняется")
        self._use("put")
        self._items[name] = value

    def delete(self, name: str) -> None:
        _validate_name(name)
        self._use("delete")
        self._items.pop(name, None)

    def _use(self, operation: str) -> None:
        left = self._failures[operation]
        if left:
            self._failures[operation] = left - 1
            raise SecretStoreError("Защищённое хранилище недоступно")


class KeyringSecretStore:
    """Системная связка паролей. В тестах эти методы не вызываются по-настоящему."""

    def get(self, name: str) -> str | None:
        _validate_name(name)
        keyring = _keyring()
        try:
            return keyring.get_password(SERVICE_NAME, name)
        except _keyring_error() as exc:
            raise SecretStoreError("Защищённое хранилище недоступно") from exc

    def put(self, name: str, value: str) -> None:
        _validate_name(name)
        if value == "":
            raise ValueError("Пустой секрет не сохраняется")
        keyring = _keyring()
        try:
            keyring.set_password(SERVICE_NAME, name, value)
        except _keyring_error() as exc:
            raise SecretStoreError("Защищённое хранилище недоступно") from exc

    def delete(self, name: str) -> None:
        _validate_name(name)
        keyring = _keyring()
        errors = _keyring_errors()
        try:
            keyring.delete_password(SERVICE_NAME, name)
        except errors.PasswordDeleteError:
            return
        except errors.KeyringError as exc:
            raise SecretStoreError("Защищённое хранилище недоступно") from exc


def _keyring():
    import keyring
    return keyring


def _keyring_error():
    from keyring.errors import KeyringError
    return KeyringError


def _keyring_errors():
    from keyring import errors
    return errors
