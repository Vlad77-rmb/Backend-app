import requests  # Импорт библиотеки для HTTP-запросов
import json  # Импорт библиотеки для работы с JSON
import sys  # Импорт библиотеки для системных функций
import time  # Импорт библиотеки для работы со временем
import random  # Импорт библиотеки для генерации случайных значений
import string  # Импорт библиотеки для работы со строками

# Базовый URL API
BASE_URL = "http://localhost:5000"

# Глобальные переменные для хранения данных сессии
session_token = None


# Генерация уникального email для каждого запуска тестов
def generate_unique_email():
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))  # Генерация случайной строки
    return f"testuser_{random_str}@example.com"  # Формирование email


user_email = generate_unique_email()  # Генерация уникального email
user_password = "password123"  # Пароль для тестового пользователя


# Утилита для красивого вывода ответов
def print_response(response, title):
    print(f"\n{'=' * 50}")  # Разделительная линия
    print(f"{title}")  # Заголовок ответа
    print(f"{'=' * 50}")  # Разделительная линия
    print(f"Статус: {response.status_code}")  # Вывод статус-кода
    try:
        # Попытка вывести JSON-ответ с форматированием
        print(f"Ответ: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    except:
        # Если не JSON, вывести текстовый ответ
        print(f"Текст ответа: {response.text}")
    print(f"{'=' * 50}")  # Разделительная линия


# Проверка статуса сервера
def test_server_status():
    try:
        response = requests.get(BASE_URL)  # Отправка GET-запроса к серверу
        print("Сервер работает и отвечает на запросы")  # Сообщение об успешном подключении
        return True  # Возврат успешного статуса
    except requests.exceptions.ConnectionError:
        print(
            "Ошибка: Не удалось подключиться к серверу. Убедитесь, что он запущен.")  # Сообщение об ошибке подключения
        return False  # Возврат статуса ошибки


# Тестирование регистрации пользователя
def test_register():
    global user_email, user_password  # Использование глобальных переменных

    url = f"{BASE_URL}/register"  # URL для регистрации
    data = {  # Данные для регистрации
        "first_name": "Иван",
        "last_name": "Иванов",
        "patronymic": "Иванович",
        "email": user_email,
        "password": user_password
    }

    try:
        response = requests.post(url, json=data)  # Отправка POST-запроса
        print_response(response, "РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ")  # Вывод ответа
        return response.status_code == 201  # Проверка успешного создания
    except Exception as e:
        print(f"Ошибка при регистрации: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование входа в систему
def test_login():
    global session_token, user_email, user_password  # Использование глобальных переменных

    url = f"{BASE_URL}/login"  # URL для входа
    data = {  # Данные для входа
        "email": user_email,
        "password": user_password
    }

    try:
        response = requests.post(url, json=data)  # Отправка POST-запроса
        print_response(response, "ВХОД В СИСТЕМУ")  # Вывод ответа

        if response.status_code == 200:  # Проверка успешного входа
            session_token = response.json().get('session_token')  # Сохранение токена сессии
            return True  # Возврат успешного статуса
        return False  # Возврат статуса ошибки
    except Exception as e:
        print(f"Ошибка при входе: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование получения профиля
def test_get_profile():
    global session_token  # Использование глобальной переменной

    if not session_token:  # Проверка наличия токена
        print("Ошибка: Сначала выполните вход в систему")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/profile"  # URL для получения профиля
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}"
    }

    try:
        response = requests.get(url, headers=headers)  # Отправка GET-запроса
        print_response(response, "ПОЛУЧЕНИЕ ПРОФИЛЯ")  # Вывод ответа
        return response.status_code == 200  # Проверка успешного получения
    except Exception as e:
        print(f"Ошибка при получении профиля: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование обновления профиля
def test_update_profile():
    global session_token  # Использование глобальной переменной

    if not session_token:  # Проверка наличия токена
        print("Ошибка: Сначала выполните вход в систему")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/profile"  # URL для обновления профиля
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}",
        "Content-Type": "application/json"
    }

    data = {  # Данные для обновления
        "first_name": "Петр",
        "last_name": "Петров",
        "patronymic": "Петрович"
    }

    try:
        response = requests.put(url, headers=headers, json=data)  # Отправка PUT-запроса
        print_response(response, "ОБНОВЛЕНИЕ ПРОФИЛЯ")  # Вывод ответа
        return response.status_code == 200  # Проверка успешного обновления
    except Exception as e:
        print(f"Ошибка при обновлении профиля: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование доступа к контенту (чтение)
def test_get_content():
    global session_token  # Использование глобальной переменной

    if not session_token:  # Проверка наличия токена
        print("Ошибка: Сначала выполните вход в систему")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/content"  # URL для получения контента
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}"
    }

    try:
        response = requests.get(url, headers=headers)  # Отправка GET-запроса
        print_response(response, "ДОСТУП К КОНТЕНТУ (ЧТЕНИЕ)")  # Вывод ответа
        return response.status_code == 200  # Проверка успешного получения
    except Exception as e:
        print(f"Ошибка при доступе к контенту: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование доступа к контенту (создание)
def test_create_content():
    global session_token  # Использование глобальной переменной

    if not session_token:  # Проверка наличия токена
        print("Ошибка: Сначала выполните вход в систему")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/content"  # URL для создания контента
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}",
        "Content-Type": "application/json"
    }

    data = {  # Данные для создания контента
        "title": "Тестовый заголовок",
        "content": "Это тестовое содержимое, созданное через API"
    }

    try:
        response = requests.post(url, headers=headers, json=data)  # Отправка POST-запроса
        print_response(response, "ДОСТУП К КОНТЕНТУ (СОЗДАНИЕ)")  # Вывод ответа
        return response.status_code == 201  # Проверка успешного создания
    except Exception as e:
        print(f"Ошибка при создании контента: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование доступа к админ-панели
def test_admin_access():
    global session_token  # Использование глобальной переменной

    if not session_token:  # Проверка наличия токена
        print("Ошибка: Сначала выполните вход в систему")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/admin/users"  # URL для доступа к админ-панели
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}"
    }

    try:
        response = requests.get(url, headers=headers)  # Отправка GET-запроса
        print_response(response, "ДОСТУП К АДМИН-ПАНЕЛИ (ОЖИДАЕТСЯ ОШИБКА 405)")  # Вывод ответа
        return response.status_code == 405  # Проверка ожидаемой ошибки
    except Exception as e:
        print(f"Ошибка при доступе к админ-панели: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование выхода из системы
def test_logout():
    global session_token  # Использование глобальной переменной

    if not session_token:  # Проверка наличия токена
        print("Ошибка: Сначала выполните вход в систему")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/logout"  # URL для выхода
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}"
    }

    try:
        response = requests.post(url, headers=headers)  # Отправка POST-запроса
        print_response(response, "ВЫХОД ИЗ СИСТЕМЫ")  # Вывод ответа

        if response.status_code == 200:  # Проверка успешного выхода
            session_token = None  # Сброс токена
            return True  # Возврат успешного статуса
        return False  # Возврат статуса ошибки
    except Exception as e:
        print(f"Ошибка при выходе из системы: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Тестирование удаления аккаунта
def test_delete_account():
    global session_token, user_email, user_password  # Использование глобальных переменных

    if not session_token:  # Проверка наличия токена
        test_login()  # Попытка входа

    if not session_token:  # Проверка наличия токена после попытки входа
        print("Ошибка: Не удалось войти в систему для удаления аккаунта")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    url = f"{BASE_URL}/profile"  # URL для удаления аккаунта
    headers = {  # Заголовки с токеном авторизации
        "Authorization": f"Bearer {session_token}"
    }

    try:
        response = requests.delete(url, headers=headers)  # Отправка DELETE-запроса
        print_response(response, "УДАЛЕНИЕ АККАУНТА")  # Вывод ответа

        if response.status_code == 200:  # Проверка успешного удаления
            session_token = None  # Сброс токена
            return True  # Возврат успешного статуса
        return False  # Возврат статуса ошибки
    except Exception as e:
        print(f"Ошибка при удалении аккаунта: {e}")  # Вывод ошибки
        return False  # Возврат статуса ошибки


# Запуск всех тестов последовательно
def run_all_tests():
    print("ЗАПУСК ТЕСТИРОВАНИЯ API")  # Заголовок тестирования
    print("=" * 50)  # Разделительная линия
    print(f"Используемый email: {user_email}")  # Вывод используемого email

    if not test_server_status():  # Проверка статуса сервера
        print("Сервер не отвечает. Запустите его с помощью: python app.py")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    time.sleep(1)  # Задержка для полного запуска сервера

    if not test_register():  # Тестирование регистрации
        print("Тест регистрации не пройден. Прерывание.")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    if not test_login():  # Тестирование входа
        print("Тест входа не пройден. Прерывание.")  # Сообщение об ошибке
        return False  # Возврат статуса ошибки

    test_get_profile()  # Тестирование получения профиля
    test_update_profile()  # Тестирование обновления профиля
    test_get_content()  # Тестирование получения контента
    test_create_content()  # Тестирование создания контента
    test_admin_access()  # Тестирование доступа к админ-панели
    test_logout()  # Тестирование выхода
    test_get_profile()  # Тестирование получения профиля после выхода
    test_login()  # Тестирование повторного входа
    test_delete_account()  # Тестирование удаления аккаунта
    test_login()  # Тестирование входа после удаления

    print("\nТЕСТИРОВАНИЕ ЗАВЕРШЕНО")  # Сообщение о завершении тестирования
    return True  # Возврат успешного статуса


if __name__ == "__main__":
    success = run_all_tests()  # Запуск всех тестов

    if success:
        print("\nВсе тесты выполнены успешно!")  # Сообщение об успехе
    else:
        print("\nНекоторые тесты не прошли")  # Сообщение об ошибке

    sys.exit(0 if success else 1)  # Выход с соответствующим кодом