"""
Tkinter интерфейс системы аутентификации с управлением сессиями.

Простыми словами. Это графическое окно приложения. Пользователь может:
- зарегистрироваться;
- войти под своим логином и паролем;
- после входа увидеть панель управления сессиями: состояние авторизации,
  активные сессии, кнопки обновления токенов, выхода из текущей сессии,
  завершения выбранной или всех сессий.

Технически модуль отделяет представление (Tkinter) от бизнес-логики.
Все операции с токенами и сессиями Delegates в auth_system, session_manager,
token_manager, refresh_token и secret_store. Значения токенов и секретов
никогда не отображаются на экране.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

import auth_system
from auth_system import get_db_connection, init_db
from secret_store import (
    KeyringSecretStore,
    MemorySecretStore,
    SecretStoreError,
    delete_refresh_secret,
    load_or_create_signing_key,
)
from session_manager import (
    authorize,
    list_sessions,
    open_session,
    refresh_session_token,
    revoke_all_sessions,
    revoke_session,
    SessionError,
)
from token_manager import (
    AccessTokenError,
    ACCESS_TTL_SECONDS,
    issue_access_token,
    verify_access_token,
)
from refresh_token import (
    RefreshTokenError,
    rotate_refresh_token,
)
from security import REFRESH_TTL_SECONDS
from proof_manager import (
    create_proof,
    create_proof_keypair,
    delete_proof_key,
    load_private_key,
    ProofError,
)

# Интервал автоматической проверки истечения Access Token (мс).
_AUTO_REFRESH_INTERVAL_MS = 10_000
# За сколько секунд до истечения Access Token начинать автоматическое обновление.
_AUTO_REFRESH_LEEWAY_SECONDS = 60


class PasswordEntry(ttk.Frame):
    """
    Поле для ввода пароля с возможностью подсмотреть введённое.

    Устроено так: внутри Frame лежит Entry с show="*" (пароль скрыт) и
    Checkbutton «Показать». Когда галочка включена, у Entry меняется
    атрибут show на пустую строку — символы становятся видимыми.

    Снаружи объект ведёт себя как обычный ttk.Entry: методы get, insert,
    delete, bind доступны через self.entry.
    """

    def __init__(self, master, width: int = 28, **kwargs):
        super().__init__(master, **kwargs)

        self._show_var = tk.BooleanVar(value=False)

        self.entry = ttk.Entry(self, width=width, show="*")
        self.entry.grid(row=0, column=0, sticky="ew")

        self._toggle_btn = ttk.Checkbutton(
            self,
            text="👁",
            variable=self._show_var,
            command=self._toggle,
            width=3,
        )
        self._toggle_btn.grid(row=0, column=1, padx=(4, 0))

        self.columnconfigure(0, weight=1)

    def _toggle(self) -> None:
        self.entry.configure(show="" if self._show_var.get() else "*")

    def get(self) -> str:
        return self.entry.get()

    def insert(self, index, text: str) -> None:
        self.entry.insert(index, text)

    def delete(self, first, last=None) -> None:
        self.entry.delete(first, last)

    def bind(self, sequence, func, add=None):  # noqa: D401
        return self.entry.bind(sequence, func, add)

    def focus_set(self) -> None:
        self.entry.focus_set()

    def is_password_visible(self) -> bool:
        return self._show_var.get()

    def toggle_password_visibility(self) -> None:
        self._show_var.set(not self._show_var.get())
        self._toggle()


class AuthApp:
    """Главное окно приложения с управлением сессиями."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Система аутентификации")
        self.root.geometry("750x650")
        self.root.resizable(True, True)

        init_db()
        self.store: KeyringSecretStore | MemorySecretStore = KeyringSecretStore()
        self.signing_key: bytes | None = None
        self._store_error = None

        try:
            self.signing_key = load_or_create_signing_key(self.store)
        except SecretStoreError as exc:
            self.signing_key = None
            self._store_error = exc

        self.current_user_id: str | None = None
        self.current_username: str | None = None
        self.current_session_id: str | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.access_expires_at: int | None = None
        self.refresh_expires_at: int | None = None

        self._refresh_job: str | None = None

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.register_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.register_frame, text="Регистрация")
        self.setup_register_tab()

        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="Вход")
        self.setup_login_tab()

        self.auth_frame = ttk.Frame(self.notebook)
        self.setup_auth_tab()

        if self._store_error is not None:
            self.root.after(
                100,
                lambda: messagebox.showerror(
                    "Хранилище секретов",
                    "Защищённое хранилище недоступно. Новые сессии создать нельзя. "
                    "Регистрация и проверка пароля по-прежнему доступны.",
                ),
            )

    def setup_register_tab(self) -> None:
        ttk.Label(self.register_frame, text="Логин:").grid(
            row=0, column=0, padx=10, pady=10, sticky="w"
        )
        self.register_username = ttk.Entry(self.register_frame, width=28)
        self.register_username.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.register_frame, text="Пароль:").grid(
            row=1, column=0, padx=10, pady=10, sticky="w"
        )
        self.register_password = PasswordEntry(self.register_frame, width=28)
        self.register_password.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        self.register_password.bind("<KeyRelease>", self.on_password_change)

        self.strength_var = tk.StringVar(value="—")
        self.strength_label = ttk.Label(
            self.register_frame,
            textvariable=self.strength_var,
            foreground="gray",
        )
        self.strength_label.grid(row=2, column=0, columnspan=2, pady=(0, 5))

        self.strength_bar = ttk.Progressbar(
            self.register_frame, orient="horizontal",
            length=280, mode="determinate", maximum=3,
        )
        self.strength_bar.grid(row=3, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(self.register_frame, text="Подтверждение:").grid(
            row=4, column=0, padx=10, pady=10, sticky="w"
        )
        self.register_confirm = PasswordEntry(self.register_frame, width=28)
        self.register_confirm.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        ttk.Button(
            self.register_frame,
            text="Зарегистрироваться",
            command=self.handle_register,
        ).grid(row=5, column=0, columnspan=2, pady=15)

        hint = f"Требования: ≥{auth_system.MIN_LENGTH} символов, цифры, заглавные и строчные буквы"
        ttk.Label(
            self.register_frame, text=hint,
            foreground="gray", font=("TkDefaultFont", 8),
        ).grid(row=6, column=0, columnspan=2, pady=(0, 5))

        ttk.Label(
            self.register_frame,
            text="Можно использовать эмодзи, кириллицу, иероглифы и др.",
            foreground="gray", font=("TkDefaultFont", 7),
        ).grid(row=7, column=0, columnspan=2, pady=(0, 5))

    def setup_login_tab(self) -> None:
        ttk.Label(self.login_frame, text="Логин:").grid(
            row=0, column=0, padx=10, pady=10, sticky="w"
        )
        self.login_username = ttk.Entry(self.login_frame, width=28)
        self.login_username.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.login_frame, text="Пароль:").grid(
            row=1, column=0, padx=10, pady=10, sticky="w"
        )
        self.login_password = PasswordEntry(self.login_frame, width=28)
        self.login_password.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        ttk.Button(
            self.login_frame, text="Войти", command=self.handle_login
        ).grid(row=2, column=0, columnspan=2, pady=20)

    def setup_auth_tab(self) -> None:
        info_frame = ttk.LabelFrame(self.auth_frame, text="Состояние авторизации")
        info_frame.pack(fill="x", padx=10, pady=(10, 5))

        self.status_var = tk.StringVar(value="Не авторизован")
        ttk.Label(info_frame, textvariable=self.status_var, font=("TkDefaultFont", 10, "bold")).pack(
            anchor="w", padx=10, pady=(5, 0)
        )

        self.access_expires_var = tk.StringVar(value="Access Token: —")
        ttk.Label(info_frame, textvariable=self.access_expires_var).pack(
            anchor="w", padx=10, pady=(0, 5)
        )

        self.refresh_expires_var = tk.StringVar(value="Refresh Token: —")
        ttk.Label(info_frame, textvariable=self.refresh_expires_var).pack(
            anchor="w", padx=10, pady=(0, 5)
        )

        btn_frame = ttk.Frame(info_frame)
        btn_frame.pack(fill="x", padx=10, pady=(0, 10))

        ttk.Button(btn_frame, text="Обновить токены", command=self.handle_refresh_tokens).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(btn_frame, text="Выйти из сессии", command=self.handle_logout).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(btn_frame, text="Завершить все сессии", command=self.handle_revoke_all).pack(
            side="left"
        )

        sessions_frame = ttk.LabelFrame(self.auth_frame, text="Активные сессии")
        sessions_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("session_id", "created", "expires", "state")
        self.sessions_tree = ttk.Treeview(
            sessions_frame, columns=columns, show="headings", selectmode="browse"
        )
        self.sessions_tree.heading("session_id", text="Идентификатор сессии")
        self.sessions_tree.heading("created", text="Создана")
        self.sessions_tree.heading("expires", text="Истекает")
        self.sessions_tree.heading("state", text="Состояние")
        self.sessions_tree.column("session_id", width=200)
        self.sessions_tree.column("created", width=140)
        self.sessions_tree.column("expires", width=140)
        self.sessions_tree.column("state", width=100)
        self.sessions_tree.pack(fill="both", expand=True, padx=5, pady=5)

        session_btn_frame = ttk.Frame(sessions_frame)
        session_btn_frame.pack(fill="x", padx=5, pady=(0, 5))

        ttk.Button(
            session_btn_frame, text="Обновить список", command=self.load_sessions_list
        ).pack(side="left", padx=(0, 5))
        ttk.Button(
            session_btn_frame, text="Завершить выбранную",
            command=self.handle_revoke_selected_session,
        ).pack(side="left")

        self.status_message_var = tk.StringVar(value="")
        self.status_message_label = ttk.Label(
            self.auth_frame, textvariable=self.status_message_var,
            foreground="red", wraplength=700,
        )
        self.status_message_label.pack(fill="x", padx=10, pady=(0, 10))

    def on_password_change(self, event=None) -> None:
        pwd = self.register_password.get()
        if not pwd:
            self.strength_var.set("—")
            self.strength_label.configure(foreground="gray")
            self.strength_bar["value"] = 0
            return

        level, comment = auth_system.rate_password(pwd)
        colors = {"Слабый": "#d9534f", "Средний": "#f0ad4e", "Стойкий": "#5cb85c"}
        values = {"Слабый": 1, "Средний": 2, "Стойкий": 3}

        self.strength_var.set(f"Стойкость: {level} — {comment}")
        self.strength_label.configure(foreground=colors[level])
        self.strength_bar["value"] = values[level]

    def handle_register(self) -> None:
        username = self.register_username.get()
        password = self.register_password.get()
        confirm = self.register_confirm.get()

        if not username or not password or not confirm:
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        success, message = auth_system.register_user(username, password, confirm)
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

    def handle_login(self) -> None:
        if self.signing_key is None:
            messagebox.showerror(
                "Ошибка",
                "Защищённое хранилище недоступно. Невозможно создать сессию.",
            )
            return

        username = self.login_username.get()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        success, message = auth_system.login_user(username, password)
        if not success:
            messagebox.showerror("Ошибка", message)
            return

        conn = get_db_connection()
        try:
            result = open_session(
                conn,
                self.store,
                self.signing_key,
                username,
            )
        except SessionError as exc:
            messagebox.showerror("Ошибка сессии", f"Не удалось создать сессию: {exc}")
            return
        except SecretStoreError:
            messagebox.showerror(
                "Ошибка хранилища",
                "Защищённое хранилище недоступно. Сессию создать нельзя.",
            )
            return
        finally:
            conn.close()

        self.current_user_id = result["user_id"]
        self.current_username = username
        self.current_session_id = result["session_id"]
        self.access_token = result["access_token"]
        self.refresh_token = result["refresh_token"]
        self.access_expires_at = result["access_expires_at"]
        self.refresh_expires_at = result["refresh_expires_at"]

        self.notebook.add(self.auth_frame, text="Сессии")
        self.notebook.select(self.auth_frame)
        self.update_auth_display()

        self.schedule_token_refresh()

        messagebox.showinfo(
            "Успех",
            f"Добро пожаловать, {username}! Сессия создана.",
        )

    def handle_logout(self) -> None:
        if self.current_session_id is None:
            messagebox.showwarning("Предупреждение", "Нет активной сессии.")
            return

        if not messagebox.askyesno(
            "Выход", "Завершить текущую сессию? Доступ к приложению будет ограничен."
        ):
            return

        conn = get_db_connection()
        try:
            revoke_session(
                conn,
                self.store,
                self.current_session_id,
                "user_logout",
            )
        except SessionError as exc:
            messagebox.showerror("Ошибка", f"Не удалось завершить сессию: {exc}")
            return
        except SecretStoreError:
            messagebox.showerror(
                "Ошибка хранилища",
                "Защищённое хранилище недоступно. Сессия может остаться активной.",
            )
            return
        finally:
            conn.close()

        self._clear_session_state()

    def handle_revoke_all(self) -> None:
        if self.current_user_id is None:
            messagebox.showwarning("Предупреждение", "Нет активных сессий.")
            return

        if not messagebox.askyesno(
            "Все сессии",
            "Завершить все сессии этого пользователя? Вы будете вышли из системы.",
        ):
            return

        conn = get_db_connection()
        try:
            revoke_all_sessions(
                conn,
                self.store,
                self.current_user_id,
            )
        except SessionError as exc:
            messagebox.showerror("Ошибка", f"Не удалось завершить сессии: {exc}")
            return
        except SecretStoreError:
            messagebox.showerror(
                "Ошибка хранилища",
                "Защищённое хранилище недоступно. Сессии могут остаться активными.",
            )
            return
        finally:
            conn.close()

        self._clear_session_state()

    def handle_revoke_selected_session(self) -> None:
        selection = self.sessions_tree.selection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Выберите сессию в списке.")
            return

        item = self.sessions_tree.item(selection[0])
        session_id = item["values"][0]

        if session_id == self.current_session_id:
            if not messagebox.askyesno(
                "Сессия",
                "Это текущая сессия. Её завершение приведёт к выходу. Продолжить?",
            ):
                return

        conn = get_db_connection()
        try:
            revoke_session(
                conn,
                self.store,
                session_id,
                "user_revoke",
            )
        except SessionError as exc:
            messagebox.showerror("Ошибка", f"Не удалось завершить сессию: {exc}")
            return
        except SecretStoreError:
            messagebox.showerror(
                "Ошибка хранилища",
                "Защищённое хранилище недоступно.",
            )
            return
        finally:
            conn.close()

        self.load_sessions_list()
        if session_id == self.current_session_id:
            self._clear_session_state()

    def handle_refresh_tokens(self) -> None:
        if self.current_session_id is None or self.refresh_token is None:
            messagebox.showwarning("Предупреждение", "Нет активной сессии для обновления.")
            return

        conn = get_db_connection()
        try:
            private_key = load_private_key(self.store, self.current_session_id)
            proof = create_proof(
                private_key,
                self.current_session_id,
                "refresh_rotation",
            )

            result = rotate_refresh_token(
                conn,
                self.store,
                self.signing_key,
                self.refresh_token,
                proof,
            )
        except RefreshTokenError as exc:
            messagebox.showerror(
                "Ошибка обновления",
                f"Токен не может быть обновлён: {exc}",
            )
            return
        except (ProofError, SecretStoreError) as exc:
            messagebox.showerror(
                "Ошибка",
                f"Не удалось выполнить обновление токенов: {exc}",
            )
            return
        finally:
            conn.close()

        self.access_token = result["access_token"]
        self.refresh_token = result["refresh_token"]
        self.access_expires_at = result["access_expires_at"]
        self.refresh_expires_at = result["refresh_expires_at"]
        self.current_session_id = result["session_id"]

        self.update_auth_display()
        self.load_sessions_list()
        messagebox.showinfo("Успех", "Токены обновлены.")

    def update_auth_display(self) -> None:
        if self.current_user_id is None:
            self.status_var.set("Не авторизован")
            self.access_expires_var.set("Access Token: —")
            self.refresh_expires_var.set("Refresh Token: —")
            return

        self.status_var.set(f"Авторизован как: {self.current_username}")

        if self.access_expires_at is not None:
            self.access_expires_var.set(
                f"Access Token истекает: {self._format_time(self.access_expires_at)}"
            )
        else:
            self.access_expires_var.set("Access Token: —")

        if self.refresh_expires_at is not None:
            self.refresh_expires_var.set(
                f"Refresh Token истекает: {self._format_time(self.refresh_expires_at)}"
            )
        else:
            self.refresh_expires_var.set("Refresh Token: —")

        self.load_sessions_list()

    def _format_time(self, timestamp: int) -> str:
        import time as _time
        return _time.strftime("%H:%M:%S %d.%m.%Y", _time.localtime(timestamp))

    def load_sessions_list(self) -> None:
        for item in self.sessions_tree.get_children():
            self.sessions_tree.delete(item)

        if self.current_user_id is None:
            return

        conn = get_db_connection()
        try:
            sessions = list_sessions(conn, self.current_user_id)
        except Exception:
            sessions = []
        finally:
            conn.close()

        import time as _time
        now = int(_time.time())
        for session in sessions:
            state = session["state"]
            if state == "active" and session["expires_at"] <= now:
                state = "expired"

            created_str = _time.strftime(
                "%H:%M:%S %d.%m.%Y", _time.localtime(session["created_at"])
            )
            expires_str = _time.strftime(
                "%H:%M:%S %d.%m.%Y", _time.localtime(session["expires_at"])
            )

            self.sessions_tree.insert(
                "", "end",
                values=(
                    session["session_id"],
                    created_str,
                    expires_str,
                    state,
                ),
            )

    def schedule_token_refresh(self) -> None:
        if self._refresh_job is not None:
            try:
                self.root.after_cancel(self._refresh_job)
            except tk.TclError:
                pass
        self._refresh_job = self.root.after(_AUTO_REFRESH_INTERVAL_MS, self.check_token_expiry)

    def check_token_expiry(self) -> None:
        if self._refresh_job is not None:
            try:
                self.root.after_cancel(self._refresh_job)
            except tk.TclError:
                pass

        if (
            self.current_session_id is None
            or self.refresh_token is None
            or self.access_expires_at is None
        ):
            return

        import time as _time
        now = int(_time.time())

        if self.access_expires_at - now > _AUTO_REFRESH_LEEWAY_SECONDS:
            self._refresh_job = self.root.after(
                _AUTO_REFRESH_INTERVAL_MS, self.check_token_expiry
            )
            return

        self._perform_auto_refresh()

    def _perform_auto_refresh(self) -> None:
        if self.current_session_id is None or self.refresh_token is None:
            return

        conn = get_db_connection()
        try:
            private_key = load_private_key(self.store, self.current_session_id)
            proof = create_proof(
                private_key,
                self.current_session_id,
                "refresh_rotation",
            )

            result = rotate_refresh_token(
                conn,
                self.store,
                self.signing_key,
                self.refresh_token,
                proof,
            )
        except (RefreshTokenError, ProofError, SecretStoreError):
            self.status_message_var.set(
                "Автоматическое обновление токенов не удалось. "
                "Попробуйте обновить вручную или войдите снова."
            )
            self._refresh_job = self.root.after(
                _AUTO_REFRESH_INTERVAL_MS, self.check_token_expiry
            )
            return
        finally:
            conn.close()

        self.access_token = result["access_token"]
        self.refresh_token = result["refresh_token"]
        self.access_expires_at = result["access_expires_at"]
        self.refresh_expires_at = result["refresh_expires_at"]
        self.current_session_id = result["session_id"]

        self.update_auth_display()
        self._refresh_job = self.root.after(
            _AUTO_REFRESH_INTERVAL_MS, self.check_token_expiry
        )

    def _clear_session_state(self) -> None:
        if self._refresh_job is not None:
            try:
                self.root.after_cancel(self._refresh_job)
            except tk.TclError:
                pass
            self._refresh_job = None

        self.current_user_id = None
        self.current_username = None
        self.current_session_id = None
        self.access_token = None
        self.refresh_token = None
        self.access_expires_at = None
        self.refresh_expires_at = None

        self.notebook.forget(self.auth_frame)
        self.notebook.select(self.login_frame)
        self.update_auth_display()
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)

def main() -> None:
    """
    Точка входа в приложение.

    Перед открытием окна убеждается, что секрет подписи либо уже лежит в keyring,
    либо создаётся один раз. Если связка паролей не отвечает, приложение всё равно
    открывается: регистрация и проверка пароля от неё не зависят, но новые сессии
    создать нельзя.
    """
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()