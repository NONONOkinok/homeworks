"""
Интеграционные тесты: проверяют полный цикл работы системы
(регистрация -> вход -> ошибки -> блокировка)

В отличие от юнит-тестов, здесь несколько функций вызываются вместе,
имитируя реальное поведение пользователя

Запуск:
    pytest test_integration.py -v
"""

import pytest
import sys
import auth_system


@pytest.fixture
def isolated_app(tmp_path, monkeypatch):
    """
    Готовит изолированное окружение для интеграционных тестов:
      * отдельная временная БД;
      * zxcvbn заменён на быструю заглушку (иначе некоторые пароли
        будут оцениваться очень долго);
      * счётчик попыток входа очищен (общая фикстура conftest.py)
    """
    db_path = tmp_path / "integration_users.db"
    monkeypatch.setattr(auth_system, "DB_FILE", str(db_path))
    monkeypatch.setattr(auth_system, "rate_password",
                        lambda pwd: ("Стойкий", "тест"))
    auth_system.init_db()
    yield


def test_full_registration_and_login(isolated_app):
    """Полный цикл: регистрация → вход с правильным паролем."""
    username = "new_user"
    password = "Registratciya123Aa"

    ok, msg = auth_system.register_user(username, password, password)
    assert ok is True, msg
    assert auth_system.db_user_exists(username)

    ok, msg = auth_system.login_user(username, password)
    assert ok is True, msg


def test_registration_password_mismatch(isolated_app):
    """Пароли не совпадают — регистрация не проходит."""
    ok, msg = auth_system.register_user("u", "Password123Aa", "Different123Aa")
    assert ok is False
    assert "не совпадают" in msg.lower()


def test_registration_duplicate_user(isolated_app):
    """Второй раз с тем же логином зарегистрироваться нельзя."""
    auth_system.register_user("dup", "Password123Aa", "Password123Aa")
    ok, _ = auth_system.register_user("dup", "Password123Aa", "Password123Aa")
    assert ok is False


def test_registration_weak_password(isolated_app):
    """Слишком простой пароль отклоняется."""
    ok, _ = auth_system.register_user("weak", "123", "123")
    assert ok is False


def test_login_wrong_password(isolated_app):
    """Неверный пароль не пускает в систему."""
    auth_system.register_user("u", "Password123Aa", "Password123Aa")
    ok, msg = auth_system.login_user("u", "WrongPassword999")
    assert ok is False
    assert "неверный" in msg.lower()


def test_login_nonexistent_user(isolated_app):
    """Несуществующий пользователь получает ошибку «не найден»."""
    ok, msg = auth_system.login_user("ghost", "Password123Aa")
    assert ok is False
    assert "не найден" in msg.lower()


def test_login_unicode_password(isolated_app):
    """Быстрый тест: логин/пароль с эмодзи и иероглифами (zxcvbn замокан)."""
    username = "unicode_user"
    password = "Test🔐密码Aa1"

    ok, _ = auth_system.register_user(username, password, password)
    assert ok is True

    ok, msg = auth_system.login_user(username, password)
    assert ok is True, msg


def test_lockout_after_failed_attempts(isolated_app):
    """После MAX_LOGIN_ATTEMPTS неудачных попыток пользователь блокируется."""
    auth_system.register_user("u", "Password123Aa", "Password123Aa")

    for _ in range(auth_system.MAX_LOGIN_ATTEMPTS):
        auth_system.login_user("u", "wrong")

    # Даже с правильным паролем вход теперь заблокирован
    ok, msg = auth_system.login_user("u", "Password123Aa")
    assert ok is False
    assert "попыток" in msg.lower()


def test_show_all_users_after_registration(isolated_app):
    """Список всех пользователей содержит всех зарегистрированных."""
    for name in ("alpha", "beta", "gamma"):
        auth_system.register_user(name, "Password123Aa", "Password123Aa")
    assert auth_system.db_get_all_users() == ["alpha", "beta", "gamma"]

# для запуска

if __name__ == "__main__":

    args = [__file__, "-v", "--tb=short"]
    sys.exit(pytest.main(args))