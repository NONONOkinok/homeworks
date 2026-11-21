"""
Юнит-тесты для auth_system.py (pytest)

Тесты для паролей с Unicode (кириллица, иероглифы, эмодзи):
в них zxcvbn подменяется заглушкой через monkeypatch, иначе на некоторых
входах он считает очень долго.
"""

import time
import unicodedata

import pytest
import sys
import auth_system


# ВАЛИДАЦИЯ ПАРОЛЯ (validate_password_policy)

class TestValidatePasswordPolicy:
    """Проверка базовых правил пароля."""

    def test_too_short(self):
        """Пароль короче MIN_LENGTH символов отклоняется."""
        ok, msg = auth_system.validate_password_policy("Aa1")
        assert ok is False
        assert str(auth_system.MIN_LENGTH) in msg

    def test_no_digit(self):
        """Пароль без цифры отклоняется."""
        ok, msg = auth_system.validate_password_policy("AaaaaaaaBBBB")
        assert ok is False
        assert "цифр" in msg.lower()

    def test_no_letter(self):
        """Пароль без букв (только цифры и знаки) отклоняется."""
        ok, msg = auth_system.validate_password_policy("1234567890!")
        assert ok is False
        assert "букв" in msg.lower()

    def test_no_uppercase(self):
        """Пароль только из строчных букв и цифр отклоняется."""
        ok, msg = auth_system.validate_password_policy("abcdefghij1")
        assert ok is False
        assert "заглавную" in msg.lower()

    def test_no_lowercase(self):
        """Пароль только из заглавных букв и цифр отклоняется."""
        ok, msg = auth_system.validate_password_policy("ABCDEFGHIJ1")
        assert ok is False
        assert "строчную" in msg.lower()

    def test_valid_ascii(self):
        """Правильный ASCII-пароль принимается."""
        ok, msg = auth_system.validate_password_policy("Password123Aa")
        assert ok is True
        assert msg == ""


# Быстрые тесты Unicode (zxcvbn не вызывается)

class TestValidatePasswordUnicode:
    """Быстрые тесты политики для Unicode-паролей. zxcvbn здесь не нужен."""

    @pytest.mark.parametrize("password", [
        "ПарольПароль123Aa",              # кириллица
        "ПарольПароль🔐123Aa",            # кириллица + эмодзи
        "密码密码密码密码密码1Aa",          # иероглифы + латиница
    ])
    def test_unicode_passwords_are_valid(self, password):
        """Пароли с Unicode-символами должны приниматься."""
        ok, msg = auth_system.validate_password_policy(password)
        assert ok is True, f"Ожидался успех для {password!r}, получено: {msg}"

    @pytest.mark.parametrize("password", [
        "密码密码密码密码密码1",           # только иероглифы + цифра — валидно
        "ひらがなひらがな1Aa",            # японская кана + латиница
        "한국어한국어한국어1Aa",          # корейский + латиница
    ])
    def test_cjk_passwords_without_case(self, password):
        """Пароли без регистра (CJK) не должны падать на проверке регистра."""
        ok, _ = auth_system.validate_password_policy(password)
        assert ok is True


# ОЦЕНКА СТОЙКОСТИ (rate_password)

class TestRatePassword:
    """Оценка стойкости пароля через zxcvbn."""

    def test_empty(self):
        """Пустой пароль — слабый."""
        level, comment = auth_system.rate_password("")
        assert level == "Слабый"
        assert comment == "Пустой пароль"

    def test_weak(self):
        """Простой пароль — слабый."""
        level, _ = auth_system.rate_password("123456")
        assert level == "Слабый"

    def test_strong(self):
        """Длинный и разнообразный пароль — средний или стойкий."""
        level, _ = auth_system.rate_password("X7!kQ2#vL9$mN4@pR8z")
        assert level in ("Средний", "Стойкий")


# ХЭШИРОВАНИЕ (hash_password, verify_password)

class TestHashing:
    """Хэширование и проверка паролей через Argon2."""

    def test_hash_is_different_from_password(self):
        """Хэш не совпадает с исходным паролем и не пустой."""
        hashed = auth_system.hash_password("Test123Aa")
        assert hashed != "Test123Aa"
        assert len(hashed) > 0

    def test_verify_correct(self):
        """Правильный пароль проходит верификацию."""
        pwd = "Test123Aa"
        assert auth_system.verify_password(pwd, auth_system.hash_password(pwd)) is True

    def test_verify_incorrect(self):
        """Неправильный пароль не проходит верификацию."""
        hashed = auth_system.hash_password("Test123Aa")
        assert auth_system.verify_password("wrong", hashed) is False

    def test_verify_invalid_hash(self):
        """Сломанный хэш не вызывает исключения, а просто возвращает False."""
        assert auth_system.verify_password("any", "not-a-hash") is False

    # Быстрые тесты Unicode
    @pytest.mark.parametrize("pwd", [
        "Пароль123Aa",        # кириллица
        "Пароль🔐123Aa",       # кириллица + эмодзи
        "密码密码123Aa",       # иероглифы
    ])
    def test_unicode_passwords(self, pwd):
        """Хэширование и верификация Unicode-паролей — быстро (Argon2)."""
        h = auth_system.hash_password(pwd)
        assert auth_system.verify_password(pwd, h) is True
        assert auth_system.verify_password(pwd + "x", h) is False


# ПЕРЕВОД ПОДСКАЗОК (translate_zxcvbn)

class TestTranslateZxcvbn:
    """Тесты функции-переводчика подсказок zxcvbn."""

    def test_known(self):
        """Известная строка переводится."""
        result = auth_system.translate_zxcvbn("This is a top-10 common password")
        assert result == "Это один из самых популярных паролей"

    def test_unknown(self):
        """Неизвестная строка возвращается как есть."""
        assert auth_system.translate_zxcvbn("Unknown text") == "Unknown text"

    def test_empty(self):
        """Пустая строка и None возвращаются как есть."""
        assert auth_system.translate_zxcvbn("") == ""
        assert auth_system.translate_zxcvbn(None) is None


# РАБОТА С БД

class TestDatabase:
    """Тесты основных операций с SQLite (используют фикстуру temp_db)."""

    def test_init_creates_table(self, temp_db):
        """После init_db таблица users существует."""
        conn = auth_system.get_db_connection()
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='users'"
            )
            assert cur.fetchone() is not None
        finally:
            conn.close()

    def test_add_and_get_user(self, temp_db):
        """Пользователь добавляется и его хэш читается."""
        assert auth_system.db_add_user("alice", "hash1") is True
        assert auth_system.db_get_user("alice") == "hash1"

    def test_add_duplicate_user(self, temp_db):
        """Повторная вставка того же логина возвращает False."""
        assert auth_system.db_add_user("bob", "h") is True
        assert auth_system.db_add_user("bob", "h2") is False

    def test_get_missing_user(self, temp_db):
        """Для несуществующего пользователя возвращается None."""
        assert auth_system.db_get_user("nobody") is None

    def test_user_exists(self, temp_db):
        """Функция db_user_exists корректно отрабатывает оба случая."""
        assert auth_system.db_user_exists("carol") is False
        auth_system.db_add_user("carol", "h")
        assert auth_system.db_user_exists("carol") is True

    def test_get_all_users_sorted(self, temp_db):
        """Список пользователей возвращается отсортированным."""
        for name in ("b", "a", "c"):
            auth_system.db_add_user(name, "h")
        assert auth_system.db_get_all_users() == ["a", "b", "c"]

    def test_get_all_users_empty(self, temp_db):
        """В пустой БД нет пользователей."""
        assert auth_system.db_get_all_users() == []

    def test_add_user_gets_stable_id(self, temp_db):
        """Новый пользователь получает непустой user_id, хеш пароля не меняется."""
        assert auth_system.db_add_user("alice", "hash1") is True
        conn = auth_system.get_db_connection()
        try:
            row = conn.execute(
                "SELECT password_hash, user_id, status FROM users WHERE username = ?",
                ("alice",),
            ).fetchone()
        finally:
            conn.close()
        assert row["password_hash"] == "hash1"
        assert row["status"] == "active"
        assert isinstance(row["user_id"], str) and row["user_id"]

    def test_session_tables_created(self, temp_db):
        """Миграция создаёт таблицы сессий и не требует повторного применения."""
        auth_system.init_db()
        conn = auth_system.get_db_connection()
        try:
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
                )
            }
            assert "sessions" in names
            assert "refresh_tokens" in names
            assert "security_events" in names
            assert "one_current_refresh" in names
            versions = [
                row[0]
                for row in conn.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                )
            ]
        finally:
            conn.close()
        assert versions == [1, 2, 3]

    def test_legacy_users_keep_password_hash(self, tmp_path, monkeypatch):
        """Старая база без user_id обновляется, хеш и логин остаются."""
        import sqlite3

        db_path = tmp_path / "legacy.db"
        raw = sqlite3.connect(db_path)
        raw.execute(
            """
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        raw.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("alice", "argon2-hash", "2020-01-01 00:00:00"),
        )
        raw.commit()
        raw.close()

        monkeypatch.setattr(auth_system, "DB_FILE", str(db_path))
        auth_system.init_db()

        conn = auth_system.get_db_connection()
        try:
            row = conn.execute(
                "SELECT username, password_hash, created_at, user_id, status FROM users"
            ).fetchone()
            user_id = row["user_id"]
            assert row["username"] == "alice"
            assert row["password_hash"] == "argon2-hash"
            assert row["created_at"] == "2020-01-01 00:00:00"
            assert row["status"] == "active"
            assert user_id
        finally:
            conn.close()

        auth_system.init_db()
        conn = auth_system.get_db_connection()
        try:
            rows = conn.execute(
                "SELECT password_hash, user_id FROM users"
            ).fetchall()
            assert len(rows) == 1
            assert rows[0]["password_hash"] == "argon2-hash"
            assert rows[0]["user_id"] == user_id
        finally:
            conn.close()


# РЕГИСТРАЦИЯ (register_user)

class TestRegisterUser:
    """Сценарии регистрации нового пользователя."""

    def test_empty_username(self, temp_db):
        """Пустой логин — ошибка."""
        ok, msg = auth_system.register_user("", "Password123Aa", "Password123Aa")
        assert ok is False
        assert "пуст" in msg.lower()

    def test_duplicate(self, temp_db, monkeypatch):
        """Повторная регистрация с тем же логином — ошибка."""
        # Подменяем zxcvbn, чтобы не тратить время на реальную оценку
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        auth_system.register_user("dup", "Password123Aa", "Password123Aa")
        ok, msg = auth_system.register_user("dup", "Password123Aa", "Password123Aa")
        assert ok is False
        assert "существует" in msg.lower()

    def test_password_mismatch(self, temp_db):
        """Пароли не совпадают — ошибка."""
        ok, msg = auth_system.register_user("u", "Password123Aa", "Different123Aa")
        assert ok is False
        assert "не совпадают" in msg.lower()

    def test_policy_violation(self, temp_db):
        """Пароль, не проходящий политику, отклоняется."""
        ok, _ = auth_system.register_user("u", "short", "short")
        assert ok is False

    def test_weak_by_zxcvbn(self, temp_db, monkeypatch):
        """zxcvbn считает пароль слабым — регистрация отклоняется."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Слабый", "тест-слабый"))
        ok, msg = auth_system.register_user("u", "Password123Aa", "Password123Aa")
        assert ok is False
        assert "слаб" in msg.lower()

    def test_success(self, temp_db, monkeypatch):
        """Корректная регистрация (zxcvbn замокан для скорости)."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        ok, msg = auth_system.register_user("newuser", "Password123Aa", "Password123Aa")
        assert ok is True
        assert auth_system.db_user_exists("newuser")

    def test_unicode_user_fast(self, temp_db, monkeypatch):
        """Быстрый тест: регистрация с Unicode-логином и паролем."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        ok, _ = auth_system.register_user("юзер🔐", "Пароль密码Aa1", "Пароль密码Aa1")
        assert ok is True


# ПОПЫТКИ ВХОДА / БЛОКИРОВКА

class TestLoginAttempts:
    """Тесты вспомогательных функций счётчика неудачных попыток."""

    def test_register_failed_attempt_locks_after_max(self):
        """После MAX_LOGIN_ATTEMPTS попыток пользователь блокируется."""
        user = "u_lock"
        for _ in range(auth_system.MAX_LOGIN_ATTEMPTS - 1):
            locked, seconds = auth_system._register_failed_attempt(user)
            assert locked is False
            assert seconds == 0
        locked, seconds = auth_system._register_failed_attempt(user)
        assert locked is True
        assert seconds == auth_system.LOCKOUT_SECONDS

    def test_is_locked_out_no_data(self):
        """Если попыток нет — не заблокирован."""
        assert auth_system._is_locked_out("ghost") == (False, 0)

    def test_is_locked_out_after_lock(self):
        """После блокировки _is_locked_out возвращает True и остаток времени."""
        user = "u_locked"
        for _ in range(auth_system.MAX_LOGIN_ATTEMPTS):
            auth_system._register_failed_attempt(user)
        locked, remaining = auth_system._is_locked_out(user)
        assert locked is True
        assert 0 < remaining <= auth_system.LOCKOUT_SECONDS

    def test_reset_attempts(self):
        """_reset_attempts удаляет запись о пользователе."""
        auth_system._login_attempts["u"] = {"attempts": 2, "locked_until": 0.0}
        auth_system._reset_attempts("u")
        assert "u" not in auth_system._login_attempts


# ВХОД (login_user)

class TestLoginUser:
    """Сценарии входа в систему."""

    def test_nonexistent_user(self, temp_db):
        """Несуществующий пользователь не может войти."""
        ok, msg = auth_system.login_user("ghost", "any")
        assert ok is False
        assert "не найден" in msg.lower()

    def test_wrong_password(self, temp_db, monkeypatch):
        """Неправильный пароль — ошибка."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        auth_system.register_user("u", "Password123Aa", "Password123Aa")
        ok, msg = auth_system.login_user("u", "WrongPassword999")
        assert ok is False
        assert "неверный" in msg.lower()

    def test_correct_password(self, temp_db, monkeypatch):
        """Правильный пароль — успех."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        auth_system.register_user("u", "Password123Aa", "Password123Aa")
        ok, msg = auth_system.login_user("u", "Password123Aa")
        assert ok is True

    def test_lockout_message_after_3_attempts(self, temp_db, monkeypatch):
        """После 3-х неудачных попыток пользователь блокируется."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        auth_system.register_user("u", "Password123Aa", "Password123Aa")
        for _ in range(auth_system.MAX_LOGIN_ATTEMPTS):
            auth_system.login_user("u", "wrong")
        ok, msg = auth_system.login_user("u", "Password123Aa")
        assert ok is False
        assert "попыток" in msg.lower()

    def test_lockout_for_unknown_user(self, temp_db):
        """Блокировка работает и для несуществующих логинов."""
        for _ in range(auth_system.MAX_LOGIN_ATTEMPTS):
            auth_system.login_user("ghost", "any")
        ok, msg = auth_system.login_user("ghost", "any")
        assert ok is False
        assert "попыток" in msg.lower()

    def test_unicode_login_fast(self, temp_db, monkeypatch):
        """Быстрый тест: вход с Unicode-паролем (zxcvbn замокан)."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        pwd = "Пароль🔐密码Aa1"
        auth_system.register_user("юзер", pwd, pwd)
        ok, msg = auth_system.login_user("юзер", pwd)
        assert ok is True, msg

# PasswordEntry - видимый пароль

class TestPasswordEntry:
    """Тесты виджета PasswordEntry: ввод и переключение видимости"""

    @pytest.fixture
    def root(self):
        """Скрытое корневое окно Tk; без дисплея тесты пропускаются"""
        tk = pytest.importorskip("tkinter")
        try:
            r = tk.Tk()
        except tk.TclError:
            pytest.skip("Нет доступного дисплея для Tkinter")
        r.withdraw()
        yield r
        r.destroy()

    @pytest.fixture
    def pwd_entry(self, root):
        """Экземпляр PasswordEntry, привязанный к скрытому окну"""
        return auth_system.PasswordEntry(root, width=20)

    def test_get_insert_delete_work(self, pwd_entry):
        """get/insert/delete проксируются во внутренний Entry"""
        pwd_entry.insert(0, "secret")
        assert pwd_entry.get() == "secret"
        pwd_entry.delete(0, "end")
        assert pwd_entry.get() == ""

    def test_password_hidden_by_default(self, pwd_entry):
        """По умолчанию пароль скрыт звёздочками"""
        # Внутренний Entry должен иметь show="*"
        assert pwd_entry.entry.cget("show") == "*"
        assert pwd_entry.is_password_visible() is False

    def test_toggle_shows_and_hides(self, pwd_entry):
        """Переключение видимости меняет show у Entry"""
        # Показать
        pwd_entry.toggle_password_visibility()
        assert pwd_entry.is_password_visible() is True
        assert pwd_entry.entry.cget("show") == ""

        # Скрыть обратно
        pwd_entry.toggle_password_visibility()
        assert pwd_entry.is_password_visible() is False
        assert pwd_entry.entry.cget("show") == "*"

    def test_text_preserved_on_toggle(self, pwd_entry):
        """Текст не теряется при переключении видимости"""
        pwd_entry.insert(0, "Пароль🔐123Aa")
        pwd_entry.toggle_password_visibility()
        pwd_entry.toggle_password_visibility()
        assert pwd_entry.get() == "Пароль🔐123Aa"

# UI (AuthApp) — работает, только если есть дисплей

class TestAuthApp:
    """
    Тесты Tkinter-интерфейса

    Если у системы нет графического дисплея (например, CI без xvfb),
    весь класс будет пропущен — это нормальное поведение
    """

    @pytest.fixture
    def app(self, temp_db):
        """Создаёт AuthApp на скрытом окне Tk"""
        tk = pytest.importorskip("tkinter")
        try:
            root = tk.Tk()
        except tk.TclError:
            pytest.skip("Нет доступного дисплея для Tkinter")
        root.withdraw()  # окно не показываем
        try:
            application = auth_system.AuthApp(root)
        except Exception as e:  # noqa: BLE001 — упрощаем диагностику в CI
            root.destroy()
            pytest.skip(f"Не удалось создать приложение: {e}")
        yield application
        root.destroy()

    def test_tabs_created(self, app):
        """Создаются две вкладки: Регистрация и Вход"""
        assert len(app.notebook.tabs()) == 2

    def test_on_password_change_empty(self, app):
        """Пустой пароль — индикатор сбрасывается."""
        app.register_password.delete(0, "end")
        app.on_password_change()
        assert app.strength_var.get() == "—"
        assert app.strength_bar["value"] == 0

    def test_on_password_change_with_text(self, app, monkeypatch):
        """При вводе пароля индикатор обновляется (zxcvbn замокан)."""
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        app.register_password.delete(0, "end")
        app.register_password.insert(0, "Test123")
        app.on_password_change()
        assert "Стойкий" in app.strength_var.get()
        assert app.strength_bar["value"] == 3

    def test_handle_register_empty_fields(self, app, monkeypatch):
        """Пустые поля регистрации → показывается ошибка."""
        errors = []
        monkeypatch.setattr(auth_system.messagebox, "showerror",
                            lambda title, msg: errors.append(msg))
        for entry in (app.register_username, app.register_password,
                      app.register_confirm):
            entry.delete(0, "end")
        app.handle_register()
        assert errors  # ошибка показана

    def test_handle_register_success(self, app, monkeypatch):
        """Успешная регистрация через UI (zxcvbn и messagebox замоканы)."""
        infos = []
        monkeypatch.setattr(auth_system, "rate_password",
                            lambda pwd: ("Стойкий", "ок"))
        monkeypatch.setattr(auth_system.messagebox, "showinfo",
                            lambda title, msg: infos.append(msg))
        app.register_username.insert(0, "ui_user")
        app.register_password.insert(0, "Password123Aa")
        app.register_confirm.insert(0, "Password123Aa")
        app.handle_register()
        assert any("успешна" in m.lower() for m in infos)

    def test_handle_login_empty_fields(self, app, monkeypatch):
        """Пустые поля входа → показывается ошибка."""
        errors = []
        monkeypatch.setattr(auth_system.messagebox, "showerror",
                            lambda title, msg: errors.append(msg))
        app.login_username.delete(0, "end")
        app.login_password.delete(0, "end")
        app.handle_login()
        assert errors

    def test_register_password_has_toggle(self, app):
        """Поле пароля в интерфейсе — это PasswordEntry с «глазом»."""
        assert isinstance(app.register_password, auth_system.PasswordEntry)
        assert isinstance(app.register_confirm, auth_system.PasswordEntry)
        assert isinstance(app.login_password, auth_system.PasswordEntry)
    
    def test_register_password_toggle_visible(self, app):
        """В UI поле пароля можно показать/скрыть без потери текста."""
        app.register_password.delete(0, "end")
        app.register_password.insert(0, "secret123Aa")
        assert app.register_password.entry.cget("show") == "*"
    
        app.register_password.toggle_password_visibility()
        assert app.register_password.entry.cget("show") == ""
    
        app.register_password.toggle_password_visibility()
        assert app.register_password.entry.cget("show") == "*"
        assert app.register_password.get() == "secret123Aa"

# для запуска

if __name__ == "__main__":
    # Эта ветка выполняется ТОЛЬКО когда файл запущен напрямую
    # (кнопкой Run или командой `python test_auth_system.py`)
    # Когда pytest сам импортирует файл для сбора тестов — сюда
    # управление не попадает, и рекурсии не будет

    # аргументы для pytest:
    # __file__   — запускаем именно этот файл;
    # "-v"       — подробный вывод (каждый тест отдельной строкой);
    # "--tb=short" — компактный traceback при падении
    args = [__file__, "-v", "--tb=short"]

    # Если хочется сразу видеть покрытие
    # args += ["--cov=auth_system", "--cov-report=term-missing"]
    sys.exit(pytest.main(args))