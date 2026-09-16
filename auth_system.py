import math
import json # для файла пользователя
import os # для взаисодействия с файлами 
import re # Для работы с регулярными выражениями
import tkinter as tk # для оконных приложений (тут для интерфейса)
import time
from datetime import datetime
from tkinter import messagebox, ttk # messagebox для диалогов, ttk для вкладок
from zxcvbn import zxcvbn # самые частые пароли

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Конфигурация
USERS_FILE = "users.json"  # файл для хранения пользователей

MIN_LENGTH = 10 # минимальная длина пароля
SPECIAL_CHARS = r"""#!@$%^&*()_+\-=\[\]{};':"\\|,.<>/?`~"""

# Ограничение попыток входа
MAX_LOGIN_ATTEMPTS = 3          # максимум попыток
LOCKOUT_SECONDS = 120           # блокировка на 2 минуты

# Хранилище в памяти: {username: {"attempts": int, "locked_until": float}}
_login_attempts: dict[str, dict] = {}

# Единый объект хэшера
ph = PasswordHasher() # По умолчанию: time_cost=3, memory_cost=64 MiB, parallelism=4

# РАБОТА С ПОЛЬЗОВАТЕЛЯМИ 
def load_users() -> dict:
    """Загружает список пользователей из JSON-файла."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_users(users: dict) -> None:
    """Сохраняет список пользователей в JSON-файл."""
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def hash_password(password: str) -> str:
    # Хэширует пароль через Argon2 (соль генерируется автоматически)
    return ph.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Проверяет пароль против сохранённого Argon2-хэша."""
    try:
        ph.verify(hashed_password, password)
        # Если параметры хэша устарели — можно перехэшировать (опционально)
        if ph.check_needs_rehash(hashed_password):
            # В реальном приложении здесь можно обновить хэш в БД
            pass
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

# Русские переводы feedback от zxcvbn
ZXCVBN_TRANSLATIONS = {
    # предупреждения
    "This is a top-10 common password.":
        "Это один из 10 самых популярных паролей.",
    "This is a top-100 common password.":
        "Это один из 100 самых популярных паролей.",
    "This is a very common password.":
        "Это очень распространённый пароль.",
    "This is similar to a commonly used password.":
        "Пароль похож на часто используемый.",
    "A word by itself is easy to guess.":
        "Одно слово легко угадать.",
    "Names and surnames by themselves are easy to guess.":
        "Имена и фамилии легко угадать.",
    "Common names and surnames are easy to guess.":
        "Распространённые имена и фамилии легко угадать.",
    "Straight rows of keys are easy to guess.":
        "Прямые ряды клавиш легко угадать.",
    "Short keyboard patterns are easy to guess.":
        "Короткие клавиатурные шаблоны легко угадать.",
    "Repeats like 'aaa' are easy to guess.":
        "Повторы вроде «aaa» легко угадать.",
    "Repeats like 'abcabcabc' are only slightly harder to guess than 'abc'.":
        "Повторы вроде «abcabcabc» чуть сложнее, чем «abc».",
    "Sequences like abc or 6543 are easy to guess.":
        "Последовательности вроде «abc» или «6543» легко угадать.",
    "Recent years are easy to guess.":
        "Недавние годы легко угадать.",
    "Dates are often easy to guess.":
        "Даты часто легко угадать.",
    "This is a top-10 common password":
        "Это один из 10 самых популярных паролей.",
    "This is a top-100 common password":
        "Это один из 100 самых популярных паролей.",
    "This is a very common password":
        "Это очень распространённый пароль.",
    "This is similar to a commonly used password":
        "Пароль похож на часто используемый.",
    "A word by itself is easy to guess":
        "Одно слово легко угадать.",
    "Names and surnames by themselves are easy to guess":
        "Имена и фамилии легко угадать.",
    "Common names and surnames are easy to guess":
        "Распространённые имена и фамилии легко угадать.",
    "Straight rows of keys are easy to guess":
        "Прямые ряды клавиш легко угадать.",
    "Short keyboard patterns are easy to guess":
        "Короткие клавиатурные шаблоны легко угадать.",
    "Repeats like \"aaa\" are easy to guess":
        "Повторы вроде «aaa» легко угадать.",
    "Sequences like abc or 6543 are easy to guess":
        "Последовательности вроде «abc» или «6543» легко угадать.",
    "Recent years are easy to guess":
        "Недавние годы легко угадать.",
    "Dates are often easy to guess":
        "Даты часто легко угадать.",
    "Capitalization doesn't help very much":
        "Заглавные буквы не сильно помогают.",
    "All-uppercase is almost as easy to guess as all-lowercase":
        "Всё заглавными — почти так же просто, как строчными.",
    "Reversed words aren't much harder to guess":
        "Слова наоборот угадать ненамного сложнее.",
    "Predictable substitutions like '@' instead of 'a' don't help very much":
        "Предсказуемые замены вроде «@» вместо «a» мало помогают.",
    # предложения
    "Add another word or two. Uncommon words are better.":
        "Добавьте ещё слово-два. Редкие слова лучше.",
    "Use a few words, avoid common phrases":
        "Используйте несколько слов, избегайте частых фраз.",
    "No need for symbols, digits, or uppercase letters":
        "Не нужны символы, цифры или заглавные буквы.",
    "Avoid dates and years that are associated with you":
        "Избегайте дат и годов, связанных с вами.",
    "Avoid repeated words and characters":
        "Избегайте повторяющихся слов и символов.",
    "Avoid sequences":
        "Избегайте последовательностей.",
    "Avoid recent years":
        "Избегайте недавних годов.",
    "Avoid years that are associated with you":
        "Избегайте годов, связанных с вами.",
    "Avoid common names and surnames":
        "Избегайте распространённых имён и фамилий.",
}

def translate_zxcvbn(text: str) -> str:
    """Переводит строку feedback от zxcvbn на русский"""
    if not text:
        return text
    return ZXCVBN_TRANSLATIONS.get(text, text)

# Критерии пароля

def validate_password_policy(password: str) -> tuple[bool, str]:
    """
    Проверяет базовую политику пароля
    Возвращает (ok, сообщение_об_ошибке)
    """
    if len(password) < MIN_LENGTH:
        return False, f"Пароль должен быть не короче {MIN_LENGTH} символов!"

    if not re.search(r"\d", password):
        return False, "Пароль должен содержать хотя бы одну цифру!"

    if not re.search(r"[A-Z]", password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву!"

    if not re.search(r"[a-z]", password):
        return False, "Пароль должен содержать хотя бы одну строчную букву!"

    # Спецсимволы допустимы, но не обязательны
    # if not re.search(r"[^\w\s]", password):
    #     return False, "Пароль должен содержать хотя бы один спецсимвол!"

    return True, ""

# оценка качества пароля
def rate_password(password: str) -> tuple[str, str]:
    """
    Оценивает стойкость пароля через zxcvbn.
    Возвращает (уровень, пояснение).
    Уровни: 'Слабый', 'Средний', 'Стойкий'.

    zxcvbn.score принимает значения 0..4:
        0 — очень слабый (например, "password")
        1 — слабый
        2 — средний
        3 — хороший
        4 — стойкий
    """
    if not password:
        return "Слабый", "Пустой пароль"

    # Вызов zxcvbn — он сам сверит пароль со своим словарём
    result = zxcvbn(password)
    score = result["score"]                    # 0-4 (0 = очень слабый, 4 = очень стойкий)
    guesses = result["guesses"]                # приблизительное число попыток для взлома
    feedback = result.get("feedback", {}) or {} # советы по улучшению

    # Берём warning из zxcvbn и переводим
    warning = feedback.get("warning")
    if warning:
        comment = translate_zxcvbn(warning)
    else:
        # Красивое представление порядка числа guesses
        comment = f"≈ {guesses:,} попыток подбора"

    # Маппинг score -> уровень
    if score <= 1:
        return "Слабый", comment
    elif score == 2:
        return "Средний", comment
    elif score == 3:
        return "Средний", comment   # можно оставить как «Средний» или выделить 4-й уровень
    else:  # score == 4
        return "Стойкий", comment

# Регистарция ИЛИ Вход
def register_user(username: str, password: str, confirm: str) -> tuple[bool, str]:
    users = load_users()
    username = username.strip()

    if not username:
        return False, "Логин не может быть пустым!"
    if username in users:
        return False, "Пользователь с таким именем уже существует!"
    if password != confirm:
        return False, "Пароли не совпадают!"

    # 1. Базовая политика
    ok, err = validate_password_policy(password)
    if not ok:
        return False, err

    # 2. Оценка стойкости через zxcvbn
    level, comment = rate_password(password)
    if level == "Слабый":
        return False, f"Пароль слишком слабый: {comment}"

    users[username] = hash_password(password)
    save_users(users)
    return True, "Регистрация успешна!"

def _is_locked_out(username: str) -> tuple[bool, int]:
    """
    Проверяет, заблокирован ли пользователь.
    Возвращает (заблокирован, секунд_осталось).
    """
    data = _login_attempts.get(username)
    if not data:
        return False, 0

    locked_until = data.get("locked_until", 0)
    if time.time() < locked_until:
        remaining = int(locked_until - time.time()) + 1
        return True, remaining

    # Блокировка истекла — сбрасываем счётчик
    if locked_until > 0:
        _login_attempts.pop(username, None)
    return False, 0


def _register_failed_attempt(username: str) -> tuple[bool, int]:
    """
    Регистрирует неудачную попытку.
    Возвращает (теперь_заблокирован, секунд_осталось).
    """
    data = _login_attempts.setdefault(username, {"attempts": 0, "locked_until": 0.0})
    data["attempts"] += 1

    if data["attempts"] >= MAX_LOGIN_ATTEMPTS:
        data["locked_until"] = time.time() + LOCKOUT_SECONDS
        data["attempts"] = 0   # сбрасываем счётчик, блокировка сама всё решит
        return True, LOCKOUT_SECONDS

    return False, 0


def _reset_attempts(username: str) -> None:
    """Сбрасывает счётчик попыток при успешном входе."""
    _login_attempts.pop(username, None)

def login_user(username: str, password: str) -> tuple[bool, str]:
    users = load_users()
    username = username.strip()

    # 1. Проверка блокировки
    locked, seconds = _is_locked_out(username)
    if locked:
        mins = seconds // 60
        secs = seconds % 60
        return False, (f"Слишком много попыток. "
                       f"Повторите через {mins} мин {secs} сек.")

    # 2. Проверка существования пользователя
    if username not in users:
        # Неудачная попытка — пользователя нет
        locked, seconds = _register_failed_attempt(username)
        if locked:
            return False, f"Слишком много попыток. Повторите через {seconds} сек."
        return False, "Пользователь не найден!"

    # 3. Проверка пароля
    if verify_password(password, users[username]):
        _reset_attempts(username)
        return True, "Добро пожаловать!"

    # 4. Неверный пароль
    locked, seconds = _register_failed_attempt(username)
    if locked:
        mins = seconds // 60
        secs = seconds % 60
        return False, (f"Неверный пароль. Слишком много попыток. "
                       f"Повторите через {mins} мин {secs} сек.")

    # Показываем, сколько попыток осталось
    remaining = MAX_LOGIN_ATTEMPTS - _login_attempts[username]["attempts"]
    return False, f"Неверный пароль! Осталось попыток: {remaining}"


# -=-=-=-=-=-=-=- ИНТЕРФЕЙС -=-=-=-=-=-=-=-
class AuthApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Система аутентификации (Argon2)")
        self.root.geometry("460x380")
        self.root.resizable(False, False)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.register_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.register_frame, text="Регистрация")
        self.setup_register_tab()

        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="Вход")
        self.setup_login_tab()

    # Вкладка регистрации
    def setup_register_tab(self):
        ttk.Label(self.register_frame, text="Логин:").grid(
            row=0, column=0, padx=10, pady=10, sticky="w")
        self.register_username = ttk.Entry(self.register_frame, width=28)
        self.register_username.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.register_frame, text="Пароль:").grid(
            row=1, column=0, padx=10, pady=10, sticky="w")
        self.register_password = ttk.Entry(self.register_frame, width=28, show="*")
        self.register_password.grid(row=1, column=1, padx=10, pady=10)
        # Отслеживаем ввод для динамической оценки стойкости
        self.register_password.bind("<KeyRelease>", self.on_password_change)

        # Индикатор стойкости
        self.strength_var = tk.StringVar(value="—")
        self.strength_label = ttk.Label(
            self.register_frame,
            textvariable=self.strength_var,
            foreground="gray"
        )
        self.strength_label.grid(row=2, column=0, columnspan=2, pady=(0, 5))

        # Прогресс-бар стойкости
        self.strength_bar = ttk.Progressbar(
            self.register_frame, orient="horizontal",
            length=280, mode="determinate", maximum=3
        )
        self.strength_bar.grid(row=3, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(self.register_frame, text="Подтверждение:").grid(
            row=4, column=0, padx=10, pady=10, sticky="w")
        self.register_confirm = ttk.Entry(self.register_frame, width=28, show="*")
        self.register_confirm.grid(row=4, column=1, padx=10, pady=10)

        register_btn = ttk.Button(
            self.register_frame,
            text="Зарегистрироваться",
            command=self.handle_register
        )
        register_btn.grid(row=5, column=0, columnspan=2, pady=15)

        # Подсказка о требованиях
        hint = (f"Требования: ≥{MIN_LENGTH} символов, цифры, "
                "заглавные и строчные буквы")
        ttk.Label(
            self.register_frame, text=hint,
            foreground="gray", font=("TkDefaultFont", 8)
        ).grid(row=6, column=0, columnspan=2, pady=(0, 5))

    # Вкладка входа
    def setup_login_tab(self):
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

    # Обработчики
    def on_password_change(self, event=None):
        # Обновляет индикатор стойкости при вводе пароля
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
        username = self.register_username.get().strip()
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
        username = self.login_username.get().strip()
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
        users = load_users()
        if not users:
            messagebox.showinfo("Пользователи", "Нет зарегистрированных пользователей")
        else:
            user_list = "\n".join([f"• {u}" for u in users.keys()])
            messagebox.showinfo(
                "Зарегистрированные пользователи",
                f"Всего: {len(users)}\n\n{user_list}"
            )


# Точка входа
def main():
    root = tk.Tk()
    AuthApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()