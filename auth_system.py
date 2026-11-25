"""
Система аутентификации с регистрацией и входом.
- Хранение пользователей: SQLite (файл users.db, не использует память устройства)
- Поддержка Unicode в паролях: любые символы (китайские, эмодзи, спецсимволы и т.д.)
- Переводы zxcvbn вынесены в отдельный файл translations.py
"""

import os
import re
import sqlite3
import time
import unicodedata
import uuid

from database import migrate

# Хэширование паролей
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Оценка стойкости пароля
from zxcvbn import zxcvbn

# Импорт переводов из отдельного файла
from translations import ZXCVBN_TRANSLATIONS


# КОНФИГУРАЦИЯ 

# БД создаётся в папке с файлом auth_system.py
DB_FILE = os.path.join(os.path.dirname(__file__), "users.db")

MIN_LENGTH = 10  # минимальная длина пароля

# Ограничение попыток входа
MAX_LOGIN_ATTEMPTS = 3   # максимум попыток
LOCKOUT_SECONDS = 120    # блокировка на 2 минуты

# Хранилище в памяти для блокировок
_login_attempts: dict[str, dict] = {}

# Хэшер паролей Argon2
ph = PasswordHasher()


# РАБОТА С БАЗОЙ ДАННЫХ

def get_db_connection() -> sqlite3.Connection:
    """
    Создаёт подключение к базе данных SQLite.

    foreign_keys включает связи между новыми таблицами.
    busy_timeout заставляет второй экземпляр подождать, если база занята записью.
    WAL позволяет читать базу во время записи. Это подготовка к нескольким
    окнам приложения, а не общая база между разными компьютерами.
    """
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL").fetchone()
    return conn


def init_db() -> None:
    """Создаёт и обновляет схему. Повторный запуск не трогает уже записанных пользователей."""
    conn = get_db_connection()
    try:
        with conn:
            migrate(conn)
    finally:
        conn.close()


def db_add_user(username: str, password_hash: str) -> bool:
    """Добавляет пользователя в БД. Возвращает True при успехе."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, user_id) VALUES (?, ?, ?)",
                (username, password_hash, str(uuid.uuid4())),
            )
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def db_get_user(username: str) -> str | None:
    """Возвращает хэш пароля пользователя или None."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        return row["password_hash"] if row else None
    finally:
        conn.close()


def db_user_exists(username: str) -> bool:
    """Проверяет, существует ли пользователь."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,)
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()


def db_get_all_users() -> list[str]:
    """Возвращает список всех имён пользователей."""
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT username FROM users ORDER BY username")
        return [row["username"] for row in cursor.fetchall()]
    finally:
        conn.close()


# РАБОТА С ПАРОЛЯМИ

def hash_password(password: str) -> str:
    """Хэширует пароль через Argon2. Поддерживает любые Unicode-символы."""
    return ph.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Проверяет пароль против сохранённого Argon2-хэша."""
    try:
        ph.verify(hashed_password, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def translate_zxcvbn(text: str) -> str:
    """Переводит строку feedback от zxcvbn на русский."""
    if not text:
        return text
    return ZXCVBN_TRANSLATIONS.get(text, text)


# ВАЛИДАЦИЯ ПАРОЛЯ

def validate_password_policy(password: str) -> tuple[bool, str]:
    r"""
    Проверяет базовую политику пароля.

    Правила:
      * длина не меньше MIN_LENGTH;
      * есть хотя бы одна цифра;
      * есть хотя бы одна буква;
      * если в пароле есть буквы с регистром (латиница, кириллица, греческий
        и т.п.) — нужны и заглавные, и строчные. Для письменностей без
        регистра (китайский, японский, корейский) достаточно просто буквы.

    Поддерживает Unicode: эмодзи, иероглифы, кириллицу и любые другие символы.
    """
    # 1. Проверка длины
    if len(password) < MIN_LENGTH:
        return False, f"Пароль должен быть не короче {MIN_LENGTH} символов!"

    # 2. Проверка на наличие цифры (любой Unicode-цифры)
    if not re.search(r"\d", password):
        return False, "Пароль должен содержать хотя бы одну цифру!"

    # Список Unicode-категорий символов (например, 'Lu', 'Ll', 'Lo', 'Nd', 'So')
    categories = [unicodedata.category(c) for c in password]

    # 3. Хотя бы одна буква в принципе (категории, начинающиеся с 'L')
    if not any(cat.startswith("L") for cat in categories):
        return False, "Пароль должен содержать хотя бы одну букву!"

    # 4. Если есть буквы с регистром — нужны и заглавные, и строчные
    has_cased = any(cat in ("Lu", "Ll", "Lt") for cat in categories)
    if has_cased:
        if not any(cat in ("Lu", "Lt") for cat in categories):
            return False, "Пароль должен содержать хотя бы одну заглавную букву!"
        if not any(cat == "Ll" for cat in categories):
            return False, "Пароль должен содержать хотя бы одну строчную букву!"

    return True, ""


def rate_password(password: str) -> tuple[str, str]:
    """
    Оценивает стойкость пароля через zxcvbn.
    Возвращает (уровень, пояснение).
    """
    if not password:
        return "Слабый", "Пустой пароль"

    result = zxcvbn(password)
    score = result["score"]
    guesses = result["guesses"]
    feedback = result.get("feedback", {}) or {}

    warning = feedback.get("warning")
    if warning:
        comment = translate_zxcvbn(warning)
    else:
        comment = f"≈ {guesses:,} попыток подбора"

    if score <= 1:
        return "Слабый", comment
    elif score <= 3:
        return "Средний", comment
    else:
        return "Стойкий", comment


# РЕГИСТРАЦИЯ И ВХОД

def register_user(username: str, password: str, confirm: str) -> tuple[bool, str]:
    """Регистрирует нового пользователя."""
    username = username.strip()

    if not username:
        return False, "Логин не может быть пустым!"

    if db_user_exists(username):
        return False, "Пользователь с таким именем уже существует!"

    if password != confirm:
        return False, "Пароли не совпадают!"

    # Базовая политика
    ok, err = validate_password_policy(password)
    if not ok:
        return False, err

    # Оценка стойкости
    level, comment = rate_password(password)
    if level == "Слабый":
        return False, f"Пароль слишком слабый: {comment}"

    # Сохраняем в БД
    hashed = hash_password(password)
    success = db_add_user(username, hashed)

    if success:
        return True, "Регистрация успешна!"
    else:
        return False, "Ошибка при сохранении пользователя"


def _is_locked_out(username: str) -> tuple[bool, int]:
    """Проверяет, заблокирован ли пользователь."""
    data = _login_attempts.get(username)
    if not data:
        return False, 0

    locked_until = data.get("locked_until", 0)
    if time.time() < locked_until:
        remaining = int(locked_until - time.time()) + 1
        return True, remaining

    if locked_until > 0:
        _login_attempts.pop(username, None)
    return False, 0


def _register_failed_attempt(username: str) -> tuple[bool, int]:
    """Регистрирует неудачную попытку входа."""
    data = _login_attempts.setdefault(username, {"attempts": 0, "locked_until": 0.0})
    data["attempts"] += 1

    if data["attempts"] >= MAX_LOGIN_ATTEMPTS:
        data["locked_until"] = time.time() + LOCKOUT_SECONDS
        data["attempts"] = 0
        return True, LOCKOUT_SECONDS

    return False, 0


def _reset_attempts(username: str) -> None:
    """Сбрасывает счётчик попыток при успешном входе."""
    _login_attempts.pop(username, None)


def login_user(username: str, password: str) -> tuple[bool, str]:
    """Выполняет вход пользователя."""
    username = username.strip()

    # Проверка блокировки
    locked, seconds = _is_locked_out(username)
    if locked:
        mins = seconds // 60
        secs = seconds % 60
        return False, f"Слишком много попыток. Повторите через {mins} мин {secs} сек."

    # Проверка существования пользователя
    stored_hash = db_get_user(username)
    if stored_hash is None:
        locked, seconds = _register_failed_attempt(username)
        if locked:
            return False, f"Слишком много попыток. Повторите через {seconds} сек."
        return False, "Пользователь не найден!"

    # Проверка пароля (поддержка Unicode)
    if verify_password(password, stored_hash):
        _reset_attempts(username)
        return True, "Добро пожаловать!"

    # Неверный пароль
    locked, seconds = _register_failed_attempt(username)
    if locked:
        mins = seconds // 60
        secs = seconds % 60
        return False, f"Неверный пароль. Слишком много попыток. Повторите через {mins} мин {secs} сек."

    remaining = MAX_LOGIN_ATTEMPTS - _login_attempts[username]["attempts"]
    return False, f"Неверный пароль! Осталось попыток: {remaining}"

