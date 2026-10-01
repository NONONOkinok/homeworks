"""
Система аутентификации с регистрацией и входом
- Хранение пользователей: SQLite (файл users.db, не использует память устройства)
- Поддержка Unicode в паролях: любые символы (китайские, эмодзи, спецсимволы и т.д.)
- Переводы zxcvbn вынесены в отдельный файл translations.py
"""

import os
import re
import sqlite3
import tkinter as tk
import time
import unicodedata
from tkinter import messagebox, ttk

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
    """Создаёт подключение к базе данных SQLite."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Создаёт таблицу пользователей, если её нет."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    finally:
        conn.close()


def db_add_user(username: str, password_hash: str) -> bool:
    """Добавляет пользователя в БД. Возвращает True при успехе."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
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
        return False, "Неправильный данные или пользователь не найден!" # на самом деле: "пользователь не найден", но пользователь не должен об этом знать

    # Проверка пароля (поддержка Unicode имеется)
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


# ИНТЕРФЕЙС (Tkinter)

class AuthApp:
    def __init__(self, root: tk.Tk):

        # Инициализирует главное окно приложения
        self.root = root
        self.root.title("Система аутентификации")
        self.root.geometry("460x420")
        self.root.resizable(False, False)

        # Инициализация БД при запуске
        init_db()

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Вкладка регистрации
        self.register_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.register_frame, text="Регистрация")
        self.setup_register_tab()

        # Вкладка входа
        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="Вход")
        self.setup_login_tab()

    def setup_register_tab(self):
        """
        Создаёт и размещает элементы интерфейса на вкладке «Регистрация»:
        поля для ввода логина, пароля и подтверждения, индикатор стойкости пароля,
        кнопку регистрации и текстовые подсказки.
        """
        ttk.Label(self.register_frame, text="Логин:").grid(
            row=0, column=0, padx=10, pady=10, sticky="w")
        self.register_username = ttk.Entry(self.register_frame, width=28)
        self.register_username.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.register_frame, text="Пароль:").grid(
            row=1, column=0, padx=10, pady=10, sticky="w")
        self.register_password = ttk.Entry(self.register_frame, width=28, show="*")
        self.register_password.grid(row=1, column=1, padx=10, pady=10)
        self.register_password.bind("<KeyRelease>", self.on_password_change)

        # Индикатор стойкости
        self.strength_var = tk.StringVar(value="—")
        self.strength_label = ttk.Label(
            self.register_frame,
            textvariable=self.strength_var,
            foreground="gray"
        )
        self.strength_label.grid(row=2, column=0, columnspan=2, pady=(0, 5))

        # Прогресс-бар
        self.strength_bar = ttk.Progressbar(
            self.register_frame, orient="horizontal",
            length=280, mode="determinate", maximum=3
        )
        self.strength_bar.grid(row=3, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(self.register_frame, text="Подтверждение:").grid(
            row=4, column=0, padx=10, pady=10, sticky="w")
        self.register_confirm = ttk.Entry(self.register_frame, width=28, show="*")
        self.register_confirm.grid(row=4, column=1, padx=10, pady=10)

        ttk.Button(
            self.register_frame,
            text="Зарегистрироваться",
            command=self.handle_register
        ).grid(row=5, column=0, columnspan=2, pady=15)

        # Подсказки
        hint = f"Требования: ≥{MIN_LENGTH} символов, цифры, заглавные и строчные буквы"
        ttk.Label(
            self.register_frame, text=hint,
            foreground="gray", font=("TkDefaultFont", 8)
        ).grid(row=6, column=0, columnspan=2, pady=(0, 5))

        ttk.Label(
            self.register_frame,
            text="Можно использовать эмодзи, кириллицу, иероглифы и др.",
            foreground="gray", font=("TkDefaultFont", 7)
        ).grid(row=7, column=0, columnspan=2, pady=(0, 5))

    def setup_login_tab(self):
        """
        Создаёт и размещает элементы интерфейса на вкладке «Вход»:
        поля для ввода логина и пароля, кнопку «Войти» и кнопку
        «Показать всех пользователей».
        """
        ttk.Label(self.login_frame, text="Логин:").grid(
            row=0, column=0, padx=10, pady=10, sticky="w")
        self.login_username = ttk.Entry(self.login_frame, width=28)
        self.login_username.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.login_frame, text="Пароль:").grid(
            row=1, column=0, padx=10, pady=10, sticky="w")
        self.login_password = ttk.Entry(self.login_frame, width=28, show="*")
        self.login_password.grid(row=1, column=1, padx=10, pady=10)

        ttk.Button(
            self.login_frame, text="Войти", command=self.handle_login
        ).grid(row=2, column=0, columnspan=2, pady=20)

        ttk.Button(
            self.login_frame,
            text="Показать всех пользователей",
            command=self.show_users
        ).grid(row=3, column=0, columnspan=2, pady=5)

    def on_password_change(self, event=None):
        """
        Обработчик события ввода в поле пароля на вкладке регистрации.
        Вызывается при каждом нажатии клавиши. Оценивает стойкость пароля
        с помощью функции rate_password и обновляет текстовый индикатор
        и прогресс-бар
        """
        pwd = self.register_password.get()
        if not pwd:
            self.strength_var.set("—")
            self.strength_label.configure(foreground="gray")
            self.strength_bar["value"] = 0
            return

        level, comment = rate_password(pwd)
        colors = {"Слабый": "#d9534f", "Средний": "#f0ad4e", "Стойкий": "#5cb85c"}
        values = {"Слабый": 1, "Средний": 2, "Стойкий": 3}

        self.strength_var.set(f"Стойкость: {level} — {comment}")
        self.strength_label.configure(foreground=colors[level])
        self.strength_bar["value"] = values[level]

    def handle_register(self):
        """
        Обработчик нажатия кнопки «Зарегистрироваться»
        Считывает логин, пароль и подтверждение из полей ввода,
        проверяет их заполненность, вызывает функцию register_user
        При успехе показывает сообщение, очищает поля и сбрасывает
        индикатор стойкости. При ошибке выводит сообщение об ошибке
        """
        username = self.register_username.get()
        password = self.register_password.get()
        confirm = self.register_confirm.get()

        if not username or not password or not confirm:
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        success, message = register_user(username, password, confirm)
        if success:
            messagebox.showinfo("Успех", message)
            self.register_username.delete(0, tk.END)
            self.register_password.delete(0, tk.END)
            self.register_confirm.delete(0, tk.END)
            self.strength_var.set("—")
            self.strength_label.configure(foreground="gray")
            self.strength_bar["value"] = 0
        else:
            messagebox.showerror("Ошибка", message)

    def handle_login(self):
        """
        Обработчик нажатия кнопки "Войти"
        Считывает логин и пароль из полей ввода, проверяет их заполненность,
        вызывает функцию login_user. При успехе показывает сообщение и
        очищает поля. При ошибке выводит сообщение об ошибке
        """
        username = self.login_username.get()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        success, message = login_user(username, password)
        if success:
            messagebox.showinfo("Успех", message)
            self.login_username.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
        else:
            messagebox.showerror("Ошибка", message)

    def show_users(self):
        """
        Обработчик нажатия кнопки «Показать всех пользователей».
        Получает список логинов из базы данных с помощью db_get_all_users
        и отображает их в информационном окне. Если пользователей нет,
        выводит соответствующее сообщение
        """
        users = db_get_all_users()
        if not users:
            messagebox.showinfo("Пользователи", "Нет зарегистрированных пользователей")
        else:
            user_list = "\n".join([f"- {u}" for u in users])
            messagebox.showinfo(
                "Зарегистрированные пользователи",
                f"Всего: {len(users)}\n\n{user_list}"
            )


# ТОЧКА ВХОДА

def main():
    root = tk.Tk()
    AuthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()