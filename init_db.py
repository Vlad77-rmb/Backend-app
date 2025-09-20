import sqlite3
from app import app  # Импорт экземпляра приложения Flask


def init_db():
    with app.app_context():  # Работа в контексте приложения Flask
        # Установка соединения с базой данных (файл указан в конфигурации app)
        db = sqlite3.connect(app.config['DATABASE'])

        # Открытие и выполнение SQL-скрипта из файла schema.sql
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())  # Выполнение всего скрипта

        db.commit()  # Фиксация изменений в базе данных
        print("База данных успешно инициализирована!")  # Сообщение об успехе


if __name__ == '__main__':
    # Точка входа при запуске скрипта напрямую
    init_db()  # Вызов функции инициализации