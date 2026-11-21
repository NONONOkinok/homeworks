"""
Хранилище секретов. Настоящий keyring здесь не вызывается:
общая фикстура conftest.py перехватывает его функции.
"""

import pytest
from keyring.errors import KeyringError, PasswordDeleteError

import keyring
import secret_store
from secret_store import (
    SIGNING_KEY_NAME,
    MemorySecretStore,
    SecretStoreError,
    delete_refresh_secret,
    load_or_create_signing_key,
    load_refresh_secret,
    save_refresh_secret,
)


class TestMemoryStore:
    """Память ведёт себя как связка: запись, чтение, повторное удаление."""

    def test_put_get_delete(self):
        store = MemorySecretStore()
        store.put("jwt-hs256-key", "abc")
        assert store.get("jwt-hs256-key") == "abc"
        store.delete("jwt-hs256-key")
        assert store.get("jwt-hs256-key") is None
        store.delete("jwt-hs256-key")

    def test_empty_value_rejected(self):
        store = MemorySecretStore()
        with pytest.raises(ValueError):
            store.put("jwt-hs256-key", "")

    def test_bad_name_rejected(self):
        store = MemorySecretStore()
        with pytest.raises(ValueError):
            store.put("has space", "x")


class TestSigningKey:
    """Секрет HS256 создаётся один раз и не подменяется при сбое."""

    def test_creates_32_byte_key_once(self):
        store = MemorySecretStore()
        first = load_or_create_signing_key(store)
        second = load_or_create_signing_key(store)
        assert first == second
        assert len(first) == 32
        assert store.get(SIGNING_KEY_NAME) == first.hex()

    def test_existing_key_is_not_replaced(self):
        store = MemorySecretStore()
        original = b"\x01" * 32
        store.put(SIGNING_KEY_NAME, original.hex())
        assert load_or_create_signing_key(store) == original
        assert store.get(SIGNING_KEY_NAME) == original.hex()

    def test_read_error_does_not_create_another_key(self):
        store = MemorySecretStore()
        store.fail_next("get")
        with pytest.raises(SecretStoreError):
            load_or_create_signing_key(store)
        assert store.get(SIGNING_KEY_NAME) is None

    def test_write_error_does_not_leave_a_key(self):
        store = MemorySecretStore()
        store.fail_next("put")
        with pytest.raises(SecretStoreError):
            load_or_create_signing_key(store)
        assert store.get(SIGNING_KEY_NAME) is None

    def test_corrupt_key_is_not_overwritten(self):
        store = MemorySecretStore()
        store.put(SIGNING_KEY_NAME, "zz")
        with pytest.raises(SecretStoreError):
            load_or_create_signing_key(store)
        assert store.get(SIGNING_KEY_NAME) == "zz"

    def test_short_key_is_not_overwritten(self):
        store = MemorySecretStore()
        store.put(SIGNING_KEY_NAME, "aa")
        with pytest.raises(SecretStoreError):
            load_or_create_signing_key(store)
        assert store.get(SIGNING_KEY_NAME) == "aa"


class TestRefreshSecrets:
    """У разных поколений разные записи. Удаление одной не трогает остальные."""

    def test_separate_generations(self):
        store = MemorySecretStore()
        save_refresh_secret(store, "gen-1", "secret-a")
        save_refresh_secret(store, "gen-2", "secret-b")
        assert load_refresh_secret(store, "gen-1") == "secret-a"
        assert load_refresh_secret(store, "gen-2") == "secret-b"
        delete_refresh_secret(store, "gen-1")
        assert load_refresh_secret(store, "gen-1") is None
        assert load_refresh_secret(store, "gen-2") == "secret-b"

    def test_delete_missing_is_ok(self):
        delete_refresh_secret(MemorySecretStore(), "missing-gen")

    def test_bad_token_id_rejected(self):
        store = MemorySecretStore()
        with pytest.raises(ValueError):
            save_refresh_secret(store, "../jwt", "secret")

    def test_store_error_propagates(self):
        store = MemorySecretStore()
        store.fail_next("put")
        with pytest.raises(SecretStoreError):
            save_refresh_secret(store, "gen-1", "secret-a")
        assert load_refresh_secret(store, "gen-1") is None


class TestKeyringAdapter:
    """Адаптер keyring вызывается только через подмену модуля."""

    def test_roundtrip_uses_service_name(self, monkeypatch):
        data: dict[tuple[str, str], str] = {}

        def get_password(service, username):
            return data.get((service, username))

        def set_password(service, username, password):
            data[(service, username)] = password

        def delete_password(service, username):
            if (service, username) not in data:
                raise PasswordDeleteError("нет записи")
            del data[(service, username)]

        monkeypatch.setattr(keyring, "get_password", get_password)
        monkeypatch.setattr(keyring, "set_password", set_password)
        monkeypatch.setattr(keyring, "delete_password", delete_password)

        store = secret_store.KeyringSecretStore()
        save_refresh_secret(store, "gen-1", "secret-a")
        assert data[(secret_store.SERVICE_NAME, "refresh-gen-1")] == "secret-a"
        assert load_refresh_secret(store, "gen-1") == "secret-a"
        delete_refresh_secret(store, "gen-1")
        delete_refresh_secret(store, "gen-1")
        assert data == {}

    def test_backend_error_hides_details(self, monkeypatch):
        def broken(*_args, **_kwargs):
            raise KeyringError("Credential Locker path C:/secret")

        monkeypatch.setattr(keyring, "get_password", broken)
        with pytest.raises(SecretStoreError) as caught:
            secret_store.KeyringSecretStore().get(SIGNING_KEY_NAME)
        assert "Credential" not in str(caught.value)
        assert "C:/" not in str(caught.value)

    def test_signing_key_error_does_not_call_set(self, monkeypatch):
        def broken_get(*_args, **_kwargs):
            raise KeyringError("down")

        def forbidden_set(*_args, **_kwargs):
            raise AssertionError("при ошибке чтения новый секрет писать нельзя")

        monkeypatch.setattr(keyring, "get_password", broken_get)
        monkeypatch.setattr(keyring, "set_password", forbidden_set)
        with pytest.raises(SecretStoreError):
            load_or_create_signing_key(secret_store.KeyringSecretStore())
