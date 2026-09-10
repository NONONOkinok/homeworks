import bcrypt # для хэшировния
import json # для файла пользователя
import os # для взаисодействия с файлами 
import tkinter as tk # для оконных приложений (тут для интерфейса)
from tkinter import messagebox, ttk # messagebox для диалогов, ttk для вкладок

# Конфигурация
USERS_FILE = "users.json"  # файл для хранения пользователей

def load_users():
    """Загружает список пользователей из JSON-файла"""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            # Если файл повреждён, возвращаем пустой словарь
            return {}
    return {}

def save_users(users):
    #сохраняет список пользователей в JSON файл
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def hash_password(password):
    """
    Хэширует пароль с автоматической генерацией соли.
    Возвращает строку-хэш.
    """
    # Преобразуем строку пароля в байты и генерируем хэш
    salt = bcrypt.gensalt()  # автоматически генерирует "соль"
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  # возвращаем как строку

def verify_password(password, hashed_password):
    """
    Проверяет, соответствует ли введённый пароль сохранённому хэшу.
    Возвращает True или False.
    """
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except ValueError:
        # Невалидный хэш (например, повреждён)
        return False

def register_user(username, password):
    """
    Регистрирует нового пользователя.
    Возвращает True, если регистрация успешна, иначе False с сообщением.
    """
    users = load_users()
    username = username.strip()
    password = password.strip()  # Добавить эту строку

    # Проверка: логин не пустой
    if not username:
        return False, "Логин не может быть пустым!"
    
    # Проверка: существует ли пользователь?
    if username in users:
        return False, "Пользователь с таким именем уже существует!"
    
    # Проверка: пароль не слишком короткий (дополнительная защита)
    if len(password) < 4:
        return False, "Пароль должен быть не короче 4 символов!"
    
    # Хэшируем пароль и сохраняем
    users[username] = hash_password(password)
    save_users(users)
    return True, "Регистрация успешна!"

def login_user(username, password):
    """
    Проверяет вход пользователя.
    Возвращает True, если вход успешен, иначе False с сообщением.
    """
    users = load_users()
    
    # Проверка: существует ли пользователь?
    if username not in users:
        return False, "Пользователь не найден!"
    
    # Получаем сохранённый хэш
    stored_hash = users[username]
    
    # Проверяем пароль
    if verify_password(password, stored_hash):
        return True, "Добро пожаловать!"
    else:
        return False, "Неверный пароль!"

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Система аутентификации")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # Создаём вкладки для регистрации и входа
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Вкладка регистрации
        self.register_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.register_frame, text="Регистрация")
        self.setup_register_tab()
        
        # Вкладка входа
        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="Вход")
        self.setup_login_tab()
    
    def setup_register_tab(self):
        """Настройка вкладки регистрации"""
        # Метки и поля ввода
        ttk.Label(self.register_frame, text="Логин:").grid(row=0, column=0, padx=10, pady=10, sticky='w')
        self.register_username = ttk.Entry(self.register_frame, width=25)
        self.register_username.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(self.register_frame, text="Пароль:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.register_password = ttk.Entry(self.register_frame, width=25, show="*")
        self.register_password.grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(self.register_frame, text="Подтверждение:").grid(row=2, column=0, padx=10, pady=10, sticky='w')
        self.register_confirm = ttk.Entry(self.register_frame, width=25, show="*")
        self.register_confirm.grid(row=2, column=1, padx=10, pady=10)
        
        # Кнопка регистрации
        register_btn = ttk.Button(
            self.register_frame, 
            text="Зарегистрироваться", 
            command=self.handle_register
        )
        register_btn.grid(row=3, column=0, columnspan=2, pady=20)
    
    def setup_login_tab(self):
        """Настройка вкладки входа"""
        try:
            # Метки и поля ввода
            ttk.Label(self.login_frame, text="Логин:").grid(row=0, column=0, padx=10, pady=10, sticky='w')
            self.login_username = ttk.Entry(self.login_frame, width=25)
            self.login_username.grid(row=0, column=1, padx=10, pady=10)

            ttk.Label(self.login_frame, text="Пароль:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
            self.login_password = ttk.Entry(self.login_frame, width=25, show="*")
            self.login_password.grid(row=1, column=1, padx=10, pady=10)

            # Кнопка входа
            login_btn = ttk.Button(
                self.login_frame, 
                text="Войти", 
                command=self.handle_login
            )
            login_btn.grid(row=2, column=0, columnspan=2, pady=20)

            # Кнопка просмотра пользователей (для демонстрации)
            show_btn = ttk.Button(
                self.login_frame,
                text="Показать всех пользователей",
                command=self.show_users
            )
            show_btn.grid(row=3, column=0, columnspan=2, pady=10)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

    
    def handle_register(self):
        """Обработчик регистрации"""
        username = self.register_username.get().strip()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        
        # Проверка, что все поля заполнены
        if not username or not password or not confirm:
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return
        
        # Проверка совпадения паролей
        if password != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают!")
            return
        
        # Вызов функции регистрации
        success, message = register_user(username, password)
        if success:
            messagebox.showinfo("Успех", message)
            # Очищаем поля
            self.register_username.delete(0, tk.END)
            self.register_password.delete(0, tk.END)
            self.register_confirm.delete(0, tk.END)
        else:
            messagebox.showerror("Ошибка", message)
    
    def handle_login(self):
        """Обработчик входа"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return
        
        success, message = login_user(username, password)
        if success:
            messagebox.showinfo("Успех", message)
            # Очищаем поля
            self.login_username.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
        else:
            messagebox.showerror("Ошибка", message)
    
    def show_users(self):
        #Показывает всех зарегистрированных пользователей (для демонстрации)
        users = load_users()
        if not users:
            messagebox.showinfo("Пользователи", "Нет зарегистрированных пользователей")
        else:
            user_list = "\n".join([f"• {user}" for user in users.keys()])
            messagebox.showinfo("Зарегистрированные пользователи", 
                              f"Всего: {len(users)}\n\n{user_list}")

# Запуск проги

def main():
    """Точка входа в программу"""
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()