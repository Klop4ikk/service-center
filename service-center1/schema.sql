-- schema.sql - Схема базы данных для учета заявок на ремонт бытовой техники
PRAGMA foreign_keys = ON;

-- Удаляем таблицы если они существуют
DROP TABLE IF EXISTS deadline_extensions;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS repair_requests;
DROP TABLE IF EXISTS users;

-- Создаем таблицу пользователей
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fio TEXT NOT NULL,
    phone TEXT NOT NULL,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('Заказчик', 'Мастер', 'Оператор', 'Менеджер', 'admin', 'Менеджер по качеству'))
);

-- Создаем таблицу заявок на ремонт
CREATE TABLE repair_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_date DATE NOT NULL DEFAULT (CURRENT_DATE),
    home_tech_type TEXT NOT NULL,
    home_tech_model TEXT NOT NULL,
    problem_description TEXT NOT NULL,
    request_status TEXT NOT NULL DEFAULT 'Новая заявка' 
        CHECK(request_status IN ('Новая заявка', 'В процессе ремонта', 'Ожидание запчастей', 'Готова к выдаче')),
    completion_date DATE,
    repair_parts TEXT,
    master_id INTEGER,
    client_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (master_id) REFERENCES users (id) ON DELETE SET NULL,
    FOREIGN KEY (client_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Создаем таблицу комментариев
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    master_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES repair_requests (id) ON DELETE CASCADE,
    FOREIGN KEY (master_id) REFERENCES users (id)
);

-- Таблица для продления сроков (для менеджера по качеству)
CREATE TABLE deadline_extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    extended_by INTEGER NOT NULL,
    extra_days INTEGER NOT NULL,
    reason TEXT,
    extended_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES repair_requests (id),
    FOREIGN KEY (extended_by) REFERENCES users (id)
);

-- Индексы для оптимизации производительности
CREATE INDEX idx_repair_requests_client_id ON repair_requests(client_id);
CREATE INDEX idx_repair_requests_status ON repair_requests(request_status);
CREATE INDEX idx_repair_requests_master_id ON repair_requests(master_id);
CREATE INDEX idx_repair_requests_date ON repair_requests(start_date);
CREATE INDEX idx_comments_request_id ON comments(request_id);
CREATE INDEX idx_users_type ON users(type);
CREATE INDEX idx_users_login ON users(login);