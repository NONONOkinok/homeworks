""" Файл для создания и работы БД с паролями
    которые пользоваткели часто могут использовать как слишком простые """

import sqlite3
import os

DB_FILE ="passwords.db"

# Небольшой стартовый набор (топ-100). Вы легко дополните его в DB Browser,
# либо скачаете полный список (например, rockyou.txt) и импортируете.
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "1234567", "111111", "123123", "abc123",
    "1234567890", "iloveyou", "000000", "qwerty123", "1q2w3e",
    "admin", "letmein", "welcome", "monkey", "dragon",
    "sunshine", "princess", "football", "charlie", "aa123456",
    "donald", "password1", "qwerty1", "1234", "123321",
    "root", "toor", "pass", "test", "guest",
    "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "jordan23", "harley", "password123", "superman",
    "batman", "shadow", "michael", "jennifer", "hunter",
    "matrix", "pokemon", "starwars", "computer", "internet",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "987654321",
    "654321", "666666", "888888", "777777", "555555",
    "222222", "333333", "444444", "999999", "000000",
    "qwerty12345", "qwerty123456", "qwe123", "asd123", "1q2w3e4r",
    "q1w2e3r4", "q1w2e3", "1q2w3e4r5t", "zaq12wsx", "1qazxsw2",
    "admin123", "administrator", "system", "manager", "operator",
    "user", "user123", "login", "secret", "love",
    "iloveyou1", "samsung", "iphone", "android", "google",
    "facebook", "twitter", "instagram", "telegram", "whatsapp",
    "minecraft", "fortnite", "gamer", "player", "winner",
]


def create_db():
    if os.path.exists(DB_FILE):
        print(f"Файл {DB_FILE} уже существует. Удалите его вручную, если нужно пересоздать.")
        return

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Основная таблица с частыми паролями
    cur.execute("""
        CREATE TABLE common_passwords (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            password TEXT NOT NULL UNIQUE,
            rank    INTEGER              -- чем меньше, тем популярнее (опционально)
        )
    """)

    # Индекс для быстрого поиска
    cur.execute("CREATE INDEX idx_password ON common_passwords(password)")

    # Заполняем данными
    for i, pwd in enumerate(COMMON_PASSWORDS, start=1):
        cur.execute(
            "INSERT OR IGNORE INTO common_passwords (password, rank) VALUES (?, ?)",
            (pwd, i)
        )

    conn.commit()
    conn.close()
    print(f"База {DB_FILE} создана, записей: {len(COMMON_PASSWORDS)}")
    print("Откройте её в DB Browser for SQLite, чтобы дополнить список.")


if __name__ == "__main__":
    create_db()