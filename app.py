import os
import sqlite3
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, redirect, url_for, render_template_string
import hashlib
import secrets
from functools import wraps

# Инициализация Flask приложения
app = Flask(__name__)
# Указываем путь к файлу базы данных SQLite
app.config['DATABASE'] = 'auth_system.db'
# Секретный ключ для подписи сессий и токенов
app.config['SECRET_KEY'] = 'your-secret-key-here'

# HTML шаблон главной страницы с формами для тестирования API
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Система аутентификации</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .form-container { margin-bottom: 20px; padding: 15px; border: 1px solid #ccc; border-radius: 5px; }
        input, button, textarea { margin: 5px; padding: 8px; width: 300px; }
        .success { color: green; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Система аутентификации</h1>
    <p>Сервер работает! Используйте формы ниже для тестирования:</p>

    <div class="form-container">
        <h2>Регистрация (POST /register)</h2>
        <form action="/register" method="post">
            <input type="text" name="first_name" placeholder="Имя" required><br>
            <input type="text" name="last_name" placeholder="Фамилия" required><br>
            <input type="text" name="patronymic" placeholder="Отчество"><br>
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="password" placeholder="Пароль" required><br>
            <button type="submit">Зарегистрироваться</button>
        </form>
    </div>

    <div class="form-container">
        <h2>Вход (POST /login)</h2>
        <form action="/login" method="post">
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="password" placeholder="Пароль" required><br>
            <button type="submit">Войти</button>
        </form>
    </div>

    <div class="form-container">
        <h2>Работа с профилем (требует токен)</h2>
        <form action="/profile_ui" method="post">
            <input type="text" name="token" placeholder="Токен авторизации" required><br>
            <button type="submit" name="action" value="get">Получить профиль</button>
            <button type="submit" name="action" value="update">Обновить профиль</button>
            <button type="submit" name="action" value="delete">Удалить аккаунт</button>
        </form>
    </div>

    <div class="form-container">
        <h2>Работа с контентом (требует токен)</h2>
        <form action="/content_ui" method="post">
            <input type="text" name="token" placeholder="Токен авторизации" required><br>
            <button type="submit" name="action" value="get">Получить контент</button>
            <button type="submit" name="action" value="create">Создать контент</button>
        </form>
    </div>

    <div class="form-container">
        <h2>Выход из системы (требует токен)</h2>
        <form action="/logout_ui" method="post">
            <input type="text" name="token" placeholder="Токен авторизации" required><br>
            <button type="submit">Выйти</button>
        </form>
    </div>

    {% if message %}
    <div class="success">
        <h3>Результат:</h3>
        <pre>{{ message }}</pre>
    </div>
    {% endif %}

    {% if error %}
    <div class="error">
        <h3>Ошибка:</h3>
        <pre>{{ error }}</pre>
    </div>
    {% endif %}
</body>
</html>
"""

# HTML шаблон для отображения результатов операций
RESULT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Результат операции</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { color: green; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Результат операции</h1>
    {% if message %}
    <div class="success">
        <pre>{{ message }}</pre>
    </div>
    {% endif %}
    {% if error %}
    <div class="error">
        <pre>{{ error }}</pre>
    </div>
    {% endif %}
    <p><a href="/">Вернуться на главную</a></p>
</body>
</html>
"""


# Обработчик корневого URL - возвращает HTML-страницу с формами для тестирования API
@app.route('/')
def index():
    return render_template_string(INDEX_HTML)


# Обработчик для отображения результатов операций
@app.route('/result')
def show_result():
    # Получаем сообщения об успехе или ошибке из параметров запроса
    message = request.args.get('message', '')
    error = request.args.get('error', '')

    # HTML шаблон с правильной кодировкой UTF-8 для поддержки кириллицы
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Результат операции</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .success { color: green; white-space: pre-wrap; }
            .error { color: red; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <h1>Результат операции</h1>
        {% if message %}
        <div class="success">
            <pre>{{ message }}</pre>
        </div>
        {% endif %}
        {% if error %}
        <div class="error">
            <pre>{{ error }}</pre>
        </div>
        {% endif %}
        <p><a href="/">Вернуться на главную</a></p>
    </body>
    </html>
    """

    return render_template_string(html_template, message=message, error=error)


# Получение соединения с базой данных
def get_db():
    # Используем объект g Flask для хранения соединения в контексте запроса
    if 'db' not in g:
        # Устанавливаем соединение с SQLite базой данных
        g.db = sqlite3.connect(app.config['DATABASE'])
        # Настраиваем возвращение результатов в виде словарей
        g.db.row_factory = sqlite3.Row
    return g.db


# Закрытие соединения с базой данных
def close_db(e=None):
    # Извлекаем соединение из объекта g
    db = g.pop('db', None)
    # Если соединение существует, закрываем его
    if db is not None:
        db.close()


# Инициализация базы данных - создание таблиц и начальных данных
def init_db():
    with app.app_context():
        db = get_db()
        # Открываем и выполняем SQL-скрипт для создания таблиц
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


# Хеширование пароля с использованием алгоритма PBKDF2-HMAC-SHA256
def hash_password(password):
    # Генерируем случайную соль длиной 32 байта
    salt = os.urandom(32)
    # Создаем ключ с использованием PBKDF2 с 100000 итерациями
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Возвращаем комбинацию соли и ключа
    return salt + key


# Проверка пароля против хранимого хеша
def verify_password(stored_password, provided_password):
    # Извлекаем соль (первые 32 байта)
    salt = stored_password[:32]
    # Извлекаем хранимый ключ (оставшиеся байты)
    stored_key = stored_password[32:]
    # Вычисляем ключ для предоставленного пароля
    key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    # Сравниваем вычисленный ключ с хранимым
    return key == stored_key


# Декоратор для проверки аутентификации пользователя
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Получаем токен из заголовка Authorization
        token = request.headers.get('Authorization')

        # Если токена нет в заголовке, проверяем данные формы
        if not token or not token.startswith('Bearer '):
            if request.method == 'POST' and 'token' in request.form:
                token = f"Bearer {request.form['token']}"
            else:
                return jsonify({'error': 'Требуется аутентификация'}), 401

        # Извлекаем токен сессии (убираем префикс 'Bearer ')
        session_token = token[7:] if token.startswith('Bearer ') else token

        # Получаем соединение с БД
        db = get_db()

        # Ищем активную сессию с указанным токеном
        session = db.execute(
            'SELECT * FROM sessions WHERE session_token = ? AND expires_at > ?',
            (session_token, datetime.now())
        ).fetchone()

        # Если сессия не найдена или истекла, возвращаем ошибку
        if not session:
            return jsonify({'error': 'Недействительная или просроченная сессия'}), 401

        # Ищем пользователя по ID из сессии
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        # Если пользователь не найден или деактивирован, возвращаем ошибку
        if not user or not user['is_active']:
            return jsonify({'error': 'Пользователь не найден или деактивирован'}), 401

        # Сохраняем информацию о пользователе и токене в контексте запроса
        g.user = dict(user)
        g.session_token = session_token

        # Вызываем оригинальную функцию
        return f(*args, **kwargs)

    return decorated_function


# Декоратор для проверки прав доступа к ресурсу
def permission_required(permission, resource):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            # Получаем соединение с БД
            db = get_db()

            # Проверяем, есть ли у пользователя необходимое право на ресурс
            query = """
            SELECT COUNT(*) as count 
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN resource_permissions resp ON rp.permission_id = resp.permission_id
            JOIN resources r ON resp.resource_id = r.id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = ? AND p.name = ? AND r.name = ?
            """

            # Выполняем запрос к БД
            result = db.execute(query, (g.user['id'], permission, resource)).fetchone()

            # Если право доступа не найдено, возвращаем ошибку
            if result['count'] == 0:
                return jsonify({'error': 'Доступ запрещен'}), 405

            # Вызываем оригинальную функцию
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Обработчик регистрации нового пользователя
@app.route('/register', methods=['POST'])
def register():
    # Проверяем, пришли ли данные как JSON или как форма
    if request.is_json:
        data = request.get_json()
        return_json = True
    else:
        data = request.form
        return_json = False

    # Список обязательных полей
    required_fields = ['first_name', 'last_name', 'email', 'password']

    # Проверяем наличие всех обязательных полей
    if not all(field in data for field in required_fields):
        error_msg = 'Отсутствуют обязательные поля'
        if return_json:
            return jsonify({'error': error_msg}), 400
        else:
            return redirect(url_for('show_result', error=error_msg))

    # Получаем соединение с БД
    db = get_db()

    # Проверяем, существует ли уже пользователь с таким email
    existing_user = db.execute(
        'SELECT id FROM users WHERE email = ?', (data['email'],)
    ).fetchone()

    # Если пользователь уже существует, возвращаем ошибку
    if existing_user:
        error_msg = 'Пользователь с таким email уже существует'
        if return_json:
            return jsonify({'error': error_msg}), 400
        else:
            return redirect(url_for('show_result', error=error_msg))

    # Хешируем пароль перед сохранением в БД
    password_hash = hash_password(data['password'])

    # Создаем пользователя в БД
    try:
        cursor = db.execute(
            'INSERT INTO users (first_name, last_name, patronymic, email, password_hash) VALUES (?, ?, ?, ?, ?)',
            (data['first_name'], data['last_name'], data.get('patronymic'), data['email'], password_hash)
        )
        user_id = cursor.lastrowid

        # Назначаем роль "user" по умолчанию
        db.execute(
            'INSERT INTO user_roles (user_id, role_id) VALUES (?, (SELECT id FROM roles WHERE name = "user"))',
            (user_id,)
        )

        # Фиксируем изменения в БД
        db.commit()

        # Формируем сообщение об успехе
        success_msg = 'Пользователь успешно зарегистрирован'

        # Возвращаем ответ в соответствующем формате
        if return_json:
            return jsonify({'message': success_msg}), 201
        else:
            return redirect(url_for('show_result', message=success_msg))
    except sqlite3.Error as e:
        # Обрабатываем ошибки БД
        error_msg = 'Ошибка при создании пользователя'
        if return_json:
            return jsonify({'error': error_msg}), 500
        else:
            return redirect(url_for('show_result', error=error_msg))


# Обработчик аутентификации пользователя
@app.route('/login', methods=['POST'])
def login():
    # Проверяем, пришли ли данные как JSON или как форма
    if request.is_json:
        data = request.get_json()
        return_json = True
    else:
        data = request.form
        return_json = False

    # Проверяем наличие обязательных полей
    if 'email' not in data or 'password' not in data:
        error_msg = 'Email и пароль обязательны'
        if return_json:
            return jsonify({'error': error_msg}), 400
        else:
            return redirect(url_for('show_result', error=error_msg))

    # Получаем соединение с БД
    db = get_db()

    # Ищем активного пользователя по email
    user = db.execute(
        'SELECT * FROM users WHERE email = ? AND is_active = TRUE',
        (data['email'],)
    ).fetchone()

    # Проверяем пароль и существование пользователя
    if not user or not verify_password(user['password_hash'], data['password']):
        error_msg = 'Неверный email или пароль'
        if return_json:
            return jsonify({'error': error_msg}), 401
        else:
            return redirect(url_for('show_result', error=error_msg))

    # Создаем новую сессию для пользователя
    session_token = secrets.token_hex(32)  # Генерируем криптографически безопасный токен
    expires_at = datetime.now() + timedelta(days=7)  # Устанавливаем срок действия 7 дней

    # Сохраняем сессию в БД
    db.execute(
        'INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)',
        (user['id'], session_token, expires_at)
    )
    db.commit()

    # Формируем данные для ответа
    result_data = {
        'message': 'Успешный вход',
        'session_token': session_token,
        'expires_at': expires_at.isoformat()
    }

    # Возвращаем ответ в соответствующем формате
    if return_json:
        return jsonify(result_data), 200
    else:
        # Для UI показываем токен на отдельной странице
        message = f"Успешный вход!\n\nТокен: {session_token}\n\nСкопируйте этот токен для использования в других запросах."
        return redirect(url_for('show_result', message=message))


# UI-эндпоинт для работы с профилем через веб-интерфейс
@app.route('/profile_ui', methods=['POST'])
def profile_ui():
    # Получаем действие и токен из формы
    action = request.form.get('action', 'get')
    token = request.form.get('token', '')

    # Создаем заголовки с токеном для API-запросов
    headers = {'Authorization': f'Bearer {token}'}

    if action == 'get':
        # Выполняем GET-запрос к API для получения профиля
        with app.test_client() as client:
            response = client.get('/profile', headers=headers)
            return handle_api_response(response, 'Получение профиля')

    elif action == 'update':
        # Выполняем PUT-запрос к API для обновления профиля
        with app.test_client() as client:
            response = client.put('/profile', headers=headers, json={
                'first_name': 'Обновленное имя',
                'last_name': 'Обновленная фамилия'
            })
            return handle_api_response(response, 'Обновление профиля')

    elif action == 'delete':
        # Выполняем DELETE-запрос к API для удаления профиля
        with app.test_client() as client:
            response = client.delete('/profile', headers=headers)
            return handle_api_response(response, 'Удаление профиля')

    return redirect(url_for('show_result', error='Неизвестное действие'))


# UI-эндпоинт для работы с контентом через веб-интерфейс
@app.route('/content_ui', methods=['POST'])
def content_ui():
    # Получаем действие и токен из формы
    action = request.form.get('action', 'get')
    token = request.form.get('token', '')

    # Создаем заголовки с токеном для API-запросов
    headers = {'Authorization': f'Bearer {token}'}

    if action == 'get':
        # Выполняем GET-запрос к API для получения контента
        with app.test_client() as client:
            response = client.get('/content', headers=headers)
            return handle_api_response(response, 'Получение контента')

    elif action == 'create':
        # Выполняем POST-запрос к API для создания контента
        with app.test_client() as client:
            response = client.post('/content', headers=headers, json={
                'title': 'Новый контент',
                'content': 'Содержимое нового контента'
            })
            return handle_api_response(response, 'Создание контента')

    return redirect(url_for('show_result', error='Неизвестное действие'))


# UI-эндпоинт для выхода из системы через веб-интерфейс
@app.route('/logout_ui', methods=['POST'])
def logout_ui():
    # Получаем токен из формы
    token = request.form.get('token', '')

    # Создаем заголовки с токеном для API-запросов
    headers = {'Authorization': f'Bearer {token}'}

    # Выполняем POST-запрос к API для выхода из системы
    with app.test_client() as client:
        response = client.post('/logout', headers=headers)
        return handle_api_response(response, 'Выход из системы')


# Обработка ответов API для отображения в веб-интерфейсе
def handle_api_response(response, action_name):
    try:
        status_code = response.status_code
        # Получаем данные ответа, если они есть
        data = response.get_json() if response.get_data() else {}

        if 200 <= status_code < 300:
            # Успешный ответ
            message = f"{action_name} успешно!"
            if data:
                # Преобразуем Unicode escape-последовательности в читаемые символы
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
                message += f"\n\n{formatted_data}"
            return redirect(url_for('show_result', message=message))
        else:
            # Ошибка
            error_msg = f"Ошибка при {action_name}"
            if data and 'error' in data:
                error_msg += f": {data['error']}"
            elif data:
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
                error_msg += f":\n{formatted_data}"
            return redirect(url_for('show_result', error=error_msg))
    except Exception as e:
        # Обработка исключений при анализе ответа
        error_msg = f"Ошибка при {action_name}: {str(e)}"
        if hasattr(response, 'data') and response.data:
            try:
                response_data = response.get_json()
                formatted_data = json.dumps(response_data, indent=2, ensure_ascii=False)
                error_msg += f"\n\nДанные ответа: {formatted_data}"
            except:
                error_msg += f"\n\nДанные ответа: {response.data.decode('utf-8')}"
        return redirect(url_for('show_result', error=error_msg))


# API-эндпоинт для выхода из системы
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    db = get_db()
    # Удаляем текущую сессию из БД
    db.execute(
        'DELETE FROM sessions WHERE session_token = ?',
        (g.session_token,)
    )
    db.commit()

    return jsonify({'message': 'Успешный выход'}), 200


# API-эндпоинт для получения информации о текущем пользователе
@app.route('/profile', methods=['GET'])
@login_required
def get_profile():
    # Возвращаем информацию о текущем пользователе
    return jsonify({
        'id': g.user['id'],
        'first_name': g.user['first_name'],
        'last_name': g.user['last_name'],
        'patronymic': g.user['patronymic'],
        'email': g.user['email'],
        'is_active': bool(g.user['is_active'])
    }), 200


# API-эндпоинт для обновления информации профиля
@app.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.get_json()
    db = get_db()

    # Обновляем только те поля, которые предоставлены
    update_fields = []
    update_values = []

    if 'first_name' in data:
        update_fields.append('first_name = ?')
        update_values.append(data['first_name'])

    if 'last_name' in data:
        update_fields.append('last_name = ?')
        update_values.append(data['last_name'])

    if 'patronymic' in data:
        update_fields.append('patronymic = ?')
        update_values.append(data['patronymic'])

    if 'email' in data:
        # Проверяем, не используется ли email другим пользователем
        existing_user = db.execute(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            (data['email'], g.user['id'])
        ).fetchone()

        if existing_user:
            return jsonify({'error': 'Email уже используется другим пользователем'}), 400

        update_fields.append('email = ?')
        update_values.append(data['email'])

    if update_fields:
        update_values.append(g.user['id'])
        query = f'UPDATE users SET {", ".join(update_fields)} WHERE id = ?'
        db.execute(query, update_values)
        db.commit()

    return jsonify({'message': 'Профиль успешно обновлен'}), 200


# API-эндпоинт для мягкого удаления аккаунта
@app.route('/profile', methods=['DELETE'])
@login_required
def delete_profile():
    db = get_db()

    # Мягкое удаление - устанавливаем is_active = FALSE и deleted_at
    db.execute(
        'UPDATE users SET is_active = FALSE, deleted_at = ? WHERE id = ?',
        (datetime.now(), g.user['id'])
    )

    # Удаляем все сессии пользователя
    db.execute(
        'DELETE FROM sessions WHERE user_id = ?',
        (g.user['id'],)
    )

    db.commit()

    return jsonify({'message': 'Аккаунт успешно деактивирован'}), 200


# API-эндпоинт для получения списка всех пользователей
@app.route('/admin/users', methods=['GET'])
@permission_required('manage_users', 'admin_panel')
def get_users():
    db = get_db()
    # Получаем список всех пользователей с их ролями
    users = db.execute('''
        SELECT u.id, u.first_name, u.last_name, u.patronymic, u.email, u.is_active, u.created_at, u.deleted_at,
               GROUP_CONCAT(r.name) as roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        GROUP BY u.id
    ''').fetchall()

    # Формируем список пользователей для ответа
    users_list = []
    for user in users:
        users_list.append({
            'id': user['id'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'patronymic': user['patronymic'],
            'email': user['email'],
            'is_active': bool(user['is_active']),
            'created_at': user['created_at'],
            'deleted_at': user['deleted_at'],
            'roles': user['roles'].split(',') if user['roles'] else []
        })

    return jsonify(users_list), 200


# API-эндпоинт для получения контента
@app.route('/content', methods=['GET'])
@permission_required('read', 'content')
def get_content():
    # Пример защищенного ресурса
    return jsonify({'message': 'Это защищенный контент'}), 200


# API-эндпоинт для создания контента
@app.route('/content', methods=['POST'])
@permission_required('create', 'content')
def create_content():
    # Пример защищенного ресурса
    return jsonify({'message': 'Контент создан'}), 201


# Запуск приложения в режиме отладки
if __name__ == '__main__':
    app.run(debug=True)