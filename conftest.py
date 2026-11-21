"""
Общие pytest-фикстуры для тестов проекта.

Файл conftest.py pytest подхватывает автоматически — импортировать его
в тестах не нужно, а все фикстуры отсюда доступны как аргументы функций.
"""

import os
import sys

import pytest

# Делаем модули проекта (auth_system, translations) доступными для импорта,
# даже если тесты запускаются из другой директории.
_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

import auth_system


@pytest.fixture(autouse=True)
def block_real_keyring(monkeypatch):
    """
    Не даёт тестам читать и записывать настоящую связку паролей Windows.

    Код, которому нужно хранилище, получает MemorySecretStore
    или подмену функций keyring внутри конкретного теста.
    """
    import keyring

    def blocked(*_args, **_kwargs):
        raise RuntimeError("Тест обратился к настоящему keyring")

    monkeypatch.setattr(keyring, "get_password", blocked)
    monkeypatch.setattr(keyring, "set_password", blocked)
    monkeypatch.setattr(keyring, "delete_password", blocked)


@pytest.fixture(autouse=True)
def reset_login_attempts():
    """
    Автоматически очищает счётчик неудачных попыток входа
    до и после каждого теста.

    Без этого один тест мог бы «заблокировать» пользователя и сломать
    выполнение следующих тестов.
    """
    auth_system._login_attempts.clear()
    yield
    auth_system._login_attempts.clear()


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """
    Подменяет файл базы данных на временный (уникальный для каждого теста).

    Возвращает путь к тестовой БД. После теста файл удалится автоматически
    (tmp_path — встроенная фикстура pytest, тоже чистит за собой).
    """
    db_path = tmp_path / "users_test.db"
    monkeypatch.setattr(auth_system, "DB_FILE", str(db_path))
    auth_system.init_db()
    return str(db_path)