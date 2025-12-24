# database.py - Работа с базой данных SQLite
import sqlite3
import os
from flask import g

def get_db_path():
    """Возвращает путь к базе данных."""
    return os.path.join(os.path.dirname(__file__), 'service_center.db')

def get_db():
    """
    Возвращает соединение с базой данных.
    Использует глобальный контекст Flask для хранения соединения.
    """
    if 'db' not in g:
        db_path = get_db_path()
        # Создаем директорию если нужно
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        # Включаем поддержку внешних ключей
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

def close_db(e=None):
    """
    Закрывает соединение с базой данных.
    Вызывается автоматически Flask в конце запроса.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app):
    """
    Инициализирует базу данных в приложении Flask.
    Регистрирует функцию закрытия соединения.
    """
    app.teardown_appcontext(close_db)
    
    # Создаем таблицы при запуске приложения
    with app.app_context():
        db = get_db()
        
        # Проверяем, существует ли файл схемы
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if os.path.exists(schema_path):
            try:
                with open(schema_path, 'r', encoding='utf-8') as f:
                    db.executescript(f.read())
                print("✅ Схема базы данных загружена из schema.sql")
            except Exception as e:
                print(f"❌ Ошибка при чтении schema.sql: {e}")
                create_tables_directly(db)
        else:
            print("⚠️ Файл schema.sql не найден, создаю таблицы напрямую")
            create_tables_directly(db)
        
        db.commit()

def create_tables_directly(db):
    """Создает таблицы напрямую, если файл схемы не найден."""
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fio TEXT NOT NULL,
            phone TEXT NOT NULL,
            login TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('Заказчик', 'Мастер', 'Оператор', 'Менеджер', 'admin', 'Менеджер по качеству'))
        );
        
        CREATE TABLE IF NOT EXISTS repair_requests (
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
        
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            master_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES repair_requests (id) ON DELETE CASCADE,
            FOREIGN KEY (master_id) REFERENCES users (id)
        );
        
        CREATE TABLE IF NOT EXISTS deadline_extensions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            extended_by INTEGER NOT NULL,
            extra_days INTEGER NOT NULL,
            reason TEXT,
            extended_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES repair_requests (id),
            FOREIGN KEY (extended_by) REFERENCES users (id)
        );
    ''')
    print("✅ Таблицы созданы напрямую")

def query_db(query, args=(), one=False):
    """
    Удобная функция для выполнения запросов к базе данных.
    
    Args:
        query: SQL запрос
        args: Параметры запроса
        one: Если True, возвращает только одну запись
    
    Returns:
        Одна запись или список записей
    """
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    """
    Выполняет SQL команду без возврата результатов.
    
    Args:
        query: SQL команда
        args: Параметры команды
    """
    db = get_db()
    db.execute(query, args)
    db.commit()