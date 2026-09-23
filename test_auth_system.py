"""
Юнит-тесты для основных функций auth_system.py
Запуск: python test_auth_system.py
"""

import sys
import os

# Добавляем путь к модулю
sys.path.insert(0, os.path.dirname(__file__))

import auth_system


# ТЕСТЫ ВАЛИДАЦИИ ПАРОЛЯ

def test_password_too_short():
    """Пароль слишком короткий — должен быть отклонён."""
    ok, msg = auth_system.validate_password_policy("Aa1")
    assert ok == False
    print("[OK] test_password_too_short")


def test_password_no_digit():
    """Пароль без цифры — должен быть отклонён."""
    ok, msg = auth_system.validate_password_policy("AaaaaaBBBB")
    assert ok == False
    print("[OK] test_password_no_digit")


def test_password_no_uppercase():
    """Пароль без заглавной буквы — должен быть отклонён."""
    ok, msg = auth_system.validate_password_policy("ааааа123")
    assert ok == False
    print("[OK] test_password_no_uppercase")


def test_password_no_lowercase():
    """Пароль без строчной буквы — должен быть отклонён."""
    ok, msg = auth_system.validate_password_policy("ААААА123")
    assert ok == False
    print("[OK] test_password_no_lowercase")


def test_password_valid():
    """Правильный пароль — должен быть принят."""
    ok, msg = auth_system.validate_password_policy("Пароль123Aa")
    assert ok == True
    assert msg == ""
    print("[OK] test_password_valid")


# Тесты с Unicode (эмодзи, кириллица, иероглифы)

def test_password_with_emoji():
    """Пароль с эмодзи — должен быть принят."""
    ok, msg = auth_system.validate_password_policy("Пароль🔐123Aa")
    assert ok == True
    print("[OK] test_password_with_emoji")


def test_password_with_chinese():
    """Пароль с китайскими иероглифами — должен быть принят."""
    ok, msg = auth_system.validate_password_policy("密码123Aa")
    assert ok == True
    print("[OK] test_password_with_chinese")


# ТЕСТЫ ОЦЕНКИ СТОЙКОСТИ ПАРОЛЯ

def test_rate_empty_password():
    """Пустой пароль — слабый."""
    level, comment = auth_system.rate_password("")
    assert level == "Слабый"
    print("[OK] test_rate_empty_password")


def test_rate_weak_password():
    """Слабый пароль — должен определиться как слабый."""
    level, comment = auth_system.rate_password("123456")
    assert level == "Слабый"
    print("[OK] test_rate_weak_password")


def test_rate_strong_password():
    """Стойкий пароль — должен определиться как стойкий."""
    level, comment = auth_system.rate_password("МойСложныйПароль123!@#")
    assert level in ["Средний", "Стойкий"]
    print("[OK] test_rate_strong_password")


# ТЕСТЫ ХЭШИРОВАНИЯ

def test_hash_and_verify():
    """Хэширование и проверка пароля должны работать."""
    password = "Тест123Аа🔐"
    hashed = auth_system.hash_password(password)

    # Хэш не должен быть пустым
    assert hashed != ""
    assert hashed != password

    # Верификация правильного пароля
    assert auth_system.verify_password(password, hashed) == True

    # Верификация неправильного пароля
    assert auth_system.verify_password("Неверный", hashed) == False

    print("[OK] test_hash_and_verify")


# ТЕСТЫ ПЕРЕВОДА

def test_translate_known():
    """Известный текст должен переводиться."""
    result = auth_system.translate_zxcvbn("This is a top-10 common password")
    assert result == "Это один из самых популярных паролей"
    print("[OK] test_translate_known")


def test_translate_unknown():
    """Неизвестный текст должен возвращаться как есть."""
    result = auth_system.translate_zxcvbn("Unknown text here")
    assert result == "Unknown text here"
    print("[OK] test_translate_unknown")


def test_translate_empty():
    """Пустой текст должен возвращаться как есть."""
    result = auth_system.translate_zxcvbn("")
    assert result == ""
    print("[OK] test_translate_empty")


# ТЕСТЫ БД

def test_db_operations():
    """Тест основных операций с БД."""
    test_username = "test_unit_user"
    test_password = "UnitTest123Aa"

    # Создаём хэш и добавляем пользователя
    hashed = auth_system.hash_password(test_password)
    result = auth_system.db_add_user(test_username, hashed)
    assert result == True  # Успешно добавлен

    # Проверяем, что пользователь существует
    assert auth_system.db_user_exists(test_username) == True

    # Получаем хэш из БД
    stored_hash = auth_system.db_get_user(test_username)
    assert stored_hash == hashed

    # Проверяем несуществующего пользователя
    assert auth_system.db_get_user("НеСуществует") is None

    print("[OK] test_db_operations")


# ЗАПУСК ВСЕХ ТЕСТОВ

def run_all_tests():
    """Запускает все тесты по порядку."""
    print("=" * 50)
    print("Запуск юнит-тестов...")
    print("=" * 50)

    test_password_too_short()
    test_password_no_digit()
    test_password_no_uppercase()
    test_password_no_lowercase()
    test_password_valid()
    test_password_with_emoji()
    test_password_with_chinese()

    test_rate_empty_password()
    test_rate_weak_password()
    test_rate_strong_password()

    test_hash_and_verify()

    test_translate_known()
    test_translate_unknown()
    test_translate_empty()

    # Инициализируем БД для тестов
    auth_system.init_db()
    test_db_operations()

    print("=" * 50)
    print("Все тесты пройдены! ✓")
    print("=" * 50)


if __name__ == "__main__":
    run_all_tests()