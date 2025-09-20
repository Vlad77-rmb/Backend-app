-- Создание таблицы пользователей
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Уникальный идентификатор пользователя
    first_name TEXT NOT NULL,              -- Имя пользователя (обязательное поле)
    last_name TEXT NOT NULL,               -- Фамилия пользователя (обязательное поле)
    patronymic TEXT,                       -- Отчество пользователя (опциональное поле)
    email TEXT UNIQUE NOT NULL,            -- Email пользователя (уникальный, обязательное поле)
    password_hash TEXT NOT NULL,           -- Хеш пароля пользователя (обязательное поле)
    is_active BOOLEAN DEFAULT TRUE,        -- Флаг активности аккаунта (по умолчанию активен)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- Дата и время создания аккаунта
    deleted_at DATETIME NULL               -- Дата и время удаления аккаунта (мягкое удаление)
);

-- Создание таблицы ролей
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Уникальный идентификатор роли
    name TEXT UNIQUE NOT NULL,             -- Название роли (уникальное, обязательное поле)
    description TEXT                       -- Описание роли
);

-- Создание таблицы связи пользователей и ролей (многие-ко-многим)
CREATE TABLE user_roles (
    user_id INTEGER,                       -- ID пользователя (внешний ключ)
    role_id INTEGER,                       -- ID роли (внешний ключ)
    PRIMARY KEY (user_id, role_id),        -- Составной первичный ключ
    FOREIGN KEY (user_id) REFERENCES users (id),  -- Внешний ключ на таблицу users
    FOREIGN KEY (role_id) REFERENCES roles (id)   -- Внешний ключ на таблицу roles
);

-- Создание таблицы прав доступа
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Уникальный идентификатор права доступа
    name TEXT UNIQUE NOT NULL,             -- Название права доступа (уникальное, обязательное поле)
    description TEXT                       -- Описание права доступа
);

-- Создание таблицы связи ролей и прав доступа (многие-ко-многим)
CREATE TABLE role_permissions (
    role_id INTEGER,                       -- ID роли (внешний ключ)
    permission_id INTEGER,                 -- ID права доступа (внешний ключ)
    PRIMARY KEY (role_id, permission_id),  -- Составной первичный ключ
    FOREIGN KEY (role_id) REFERENCES roles (id),           -- Внешний ключ на таблицу roles
    FOREIGN KEY (permission_id) REFERENCES permissions (id)  -- Внешний ключ на таблицу permissions
);

-- Создание таблицы сессий пользователей
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Уникальный идентификатор сессии
    user_id INTEGER NOT NULL,              -- ID пользователя (внешний ключ)
    session_token TEXT UNIQUE NOT NULL,    -- Уникальный токен сессии
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- Дата и время создания сессии
    expires_at DATETIME NOT NULL,          -- Дата и время истечения сессии
    FOREIGN KEY (user_id) REFERENCES users (id)  -- Внешний ключ на таблицу users
);

-- Создание таблицы ресурсов системы
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Уникальный идентификатор ресурса
    name TEXT UNIQUE NOT NULL,             -- Название ресурса (уникальное, обязательное поле)
    description TEXT                       -- Описание ресурса
);

-- Создание таблицы связи ресурсов и прав доступа (многие-ко-многим)
CREATE TABLE resource_permissions (
    resource_id INTEGER,                   -- ID ресурса (внешний ключ)
    permission_id INTEGER,                 -- ID права доступа (внешний ключ)
    PRIMARY KEY (resource_id, permission_id),  -- Составной первичный ключ
    FOREIGN KEY (resource_id) REFERENCES resources (id),      -- Внешний ключ на таблицу resources
    FOREIGN KEY (permission_id) REFERENCES permissions (id)   -- Внешний ключ на таблицу permissions
);

-- Вставка базовых ролей системы
INSERT INTO roles (name, description) VALUES
('admin', 'Администратор системы'),        -- Роль администратора
('user', 'Обычный пользователь'),          -- Роль обычного пользователя
('moderator', 'Модератор контента');       -- Роль модератора

-- Вставка базовых прав доступа
INSERT INTO permissions (name, description) VALUES
('create', 'Создание контента'),           -- Право на создание
('read', 'Просмотр контента'),             -- Право на чтение
('update', 'Редактирование контента'),     -- Право на обновление
('delete', 'Удаление контента'),           -- Право на удаление
('manage_users', 'Управление пользователями');  -- Право на управление пользователями

-- Вставка базовых ресурсов системы
INSERT INTO resources (name, description) VALUES
('profile', 'Профиль пользователя'),       -- Ресурс профиля
('admin_panel', 'Панель администратора'),  -- Ресурс админ-панели
('content', 'Общий контент');              -- Ресурс контента

-- Назначение прав для роли администратора
INSERT INTO role_permissions (role_id, permission_id) VALUES
(1, 1), (1, 2), (1, 3), (1, 4), (1, 5);  -- admin имеет все права

-- Назначение прав для роли пользователя
INSERT INTO role_permissions (role_id, permission_id) VALUES
(2, 1), (2, 2), (2, 3);                  -- user может создавать, читать, обновлять

-- Назначение прав для роли модератора
INSERT INTO role_permissions (role_id, permission_id) VALUES
(3, 2), (3, 3), (3, 4);                  -- moderator может читать, обновлять, удалять

-- Связывание ресурсов с правами доступа
INSERT INTO resource_permissions (resource_id, permission_id) VALUES
(1, 1), (1, 2), (1, 3),                  -- profile: create, read, update
(2, 1), (2, 2), (2, 3), (2, 4), (2, 5), -- admin_panel: все права
(3, 1), (3, 2), (3, 3), (3, 4);         -- content: все права кроме manage_users