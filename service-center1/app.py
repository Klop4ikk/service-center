# app.py - ПОЛНАЯ ВЕРСИЯ системы учета заявок на ремонт бытовой техники
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_file, jsonify
from database import init_db, get_db, query_db, execute_db
import hashlib
import os
import io
import qrcode
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production-1234567890'
app.config['DATABASE'] = 'service_center.db'

# Инициализация базы данных
init_db(app)

def hash_password(password):
    """
    Хэширует пароль с использованием SHA-256.
    
    Args:
        password: Пароль в виде строки
    
    Returns:
        Хэшированный пароль
    """
    return hashlib.sha256(password.encode()).hexdigest()

@app.before_request
def load_logged_in_user():
    """
    Загружает информацию о текущем пользователе.
    Выполняется перед каждым запросом.
    """
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        user = query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)
        if user:
            g.user = dict(user)
        else:
            g.user = None
            session.clear()

def login_required(view):
    """
    Декоратор для проверки авторизации пользователя.
    
    Args:
        view: Функция представления
    
    Returns:
        Обернутую функцию или редирект на страницу входа
    """
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Для доступа к этой странице требуется авторизация.', 'warning')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def role_required(*required_types):
    """
    Декоратор для проверки типа пользователя.
    
    Args:
        *required_types: Требуемые типы пользователей
    
    Returns:
        Обернутую функцию или редирект с сообщением об ошибке
    """
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for('login'))
            
            # Администратор имеет доступ ко всему
            if g.user['type'] == 'admin':
                return view(**kwargs)
            
            # Проверяем, есть ли у пользователя нужный тип
            if g.user['type'] not in required_types:
                flash('Недостаточно прав для доступа к этой странице.', 'danger')
                return redirect(url_for('index'))
            
            return view(**kwargs)
        return wrapped_view
    return decorator

# ==================== ОСНОВНЫЕ МАРШРУТЫ ====================

@app.route('/')
@login_required
def index():
    """
    Главная страница - список заявок.
    В зависимости от типа пользователя показывает разные заявки.
    """
    # Определяем SQL запрос в зависимости от типа пользователя
    if g.user['type'] == 'Заказчик':
        # Заказчик видит только свои заявки
        requests = query_db('''
            SELECT r.*, u.fio as master_fio
            FROM repair_requests r
            LEFT JOIN users u ON r.master_id = u.id
            WHERE r.client_id = ?
            ORDER BY r.start_date DESC, r.id DESC
        ''', (g.user['id'],))
    
    elif g.user['type'] == 'Мастер':
        # Мастер видит заявки, назначенные на него
        requests = query_db('''
            SELECT r.*, uc.fio as client_fio, um.fio as master_fio
            FROM repair_requests r
            LEFT JOIN users uc ON r.client_id = uc.id
            LEFT JOIN users um ON r.master_id = um.id
            WHERE r.master_id = ?
            ORDER BY 
                CASE r.request_status
                    WHEN 'В процессе ремонта' THEN 1
                    WHEN 'Ожидание запчастей' THEN 2
                    WHEN 'Новая заявка' THEN 3
                    WHEN 'Готова к выдаче' THEN 4
                    ELSE 5
                END,
                r.start_date DESC
        ''', (g.user['id'],))
    
    else:
        # Оператор, Менеджер, Администратор видят все заявки
        requests = query_db('''
            SELECT r.*, uc.fio as client_fio, um.fio as master_fio
            FROM repair_requests r
            LEFT JOIN users uc ON r.client_id = uc.id
            LEFT JOIN users um ON r.master_id = um.id
            ORDER BY 
                CASE r.request_status
                    WHEN 'Новая заявка' THEN 1
                    WHEN 'В процессе ремонта' THEN 2
                    WHEN 'Ожидание запчастей' THEN 3
                    WHEN 'Готова к выдаче' THEN 4
                    ELSE 5
                END,
                r.start_date DESC,
                r.id DESC
        ''')
    
    return render_template('index.html', requests=requests)

@app.route('/login', methods=('GET', 'POST'))
def login():
    """
    Страница входа в систему.
    Обрабатывает форму входа и устанавливает сессию.
    """
    # Если пользователь уже авторизован, перенаправляем на главную
    if g.user is not None:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        login_input = request.form['login'].strip()
        password_input = request.form['password']
        
        # Проверяем валидность ввода
        if not login_input or not password_input:
            flash('Заполните все поля.', 'danger')
            return render_template('login.html')
        
        # Ищем пользователя в базе данных
        user = query_db(
            'SELECT * FROM users WHERE login = ?', 
            (login_input,), 
            one=True
        )
        
        # Проверяем пользователя и пароль
        if user is None or user['password_hash'] != hash_password(password_input):
            flash('Неверный логин или пароль.', 'danger')
        else:
            # Устанавливаем сессию
            session.clear()
            session['user_id'] = user['id']
            session['user_type'] = user['type']
            
            # Перенаправляем на главную
            flash(f'Добро пожаловать, {user["fio"]}!', 'success')
            return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """
    Выход из системы.
    Очищает сессию и перенаправляет на страницу входа.
    """
    user_name = g.user['fio'] if g.user else 'Пользователь'
    session.clear()
    flash(f'До свидания, {user_name}! Вы успешно вышли из системы.', 'info')
    return redirect(url_for('login'))

@app.route('/request/create', methods=('GET', 'POST'))
@login_required
@role_required('Заказчик', 'Оператор', 'admin', 'Менеджер')
def create_request():
    """
    Создание новой заявки на ремонт.
    Разные пользователи имеют разные возможности создания заявок.
    """
    if request.method == 'POST':
        # Получаем данные из формы
        home_tech_type = request.form.get('home_tech_type', '').strip()
        home_tech_model = request.form.get('home_tech_model', '').strip()
        problem_description = request.form.get('problem_description', '').strip()
        
        # Проверяем обязательные поля
        if not home_tech_type or not home_tech_model or not problem_description:
            flash('Заполните все обязательные поля.', 'danger')
            return render_template('request_create.html')
        
        # Определяем client_id в зависимости от типа пользователя
        if g.user['type'] == 'Заказчик':
            client_id = g.user['id']
        else:
            # Оператор/Менеджер может создать заявку для любого клиента
            client_id = request.form.get('client_id', g.user['id'])
        
        # Создаем заявку в базе данных
        try:
            execute_db('''
                INSERT INTO repair_requests 
                (client_id, home_tech_type, home_tech_model, problem_description) 
                VALUES (?, ?, ?, ?)
            ''', (client_id, home_tech_type, home_tech_model, problem_description))
            
            # Получаем ID созданной заявки
            new_request = query_db(
                'SELECT id FROM repair_requests WHERE client_id = ? ORDER BY id DESC LIMIT 1',
                (client_id,), one=True
            )
            
            flash(f'Заявка №{new_request["id"]} успешно создана!', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f'Ошибка при создании заявки: {str(e)}', 'danger')
            return render_template('request_create.html')
    
    # GET запрос - показываем форму
    # Если пользователь - оператор или менеджер, показываем список клиентов
    clients = None
    if g.user['type'] in ['Оператор', 'admin', 'Менеджер']:
        clients = query_db('SELECT id, fio FROM users WHERE type = "Заказчик" ORDER BY fio')
    
    return render_template('request_create.html', clients=clients)

@app.route('/request/<int:request_id>')
@login_required
def request_detail(request_id):
    """
    Детальная информация о заявке.
    Включает информацию, комментарии и формы для работы с заявкой.
    """
    # Получаем информацию о заявке
    request_data = query_db('''
        SELECT r.*, uc.fio as client_fio, um.fio as master_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        LEFT JOIN users um ON r.master_id = um.id
        WHERE r.id = ?
    ''', (request_id,), one=True)
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверяем права доступа
    if g.user['type'] == 'Заказчик' and request_data['client_id'] != g.user['id']:
        flash('У вас нет доступа к этой заявке.', 'danger')
        return redirect(url_for('index'))
    
    # Получаем комментарии к заявке
    comments = query_db('''
        SELECT c.*, u.fio as master_fio
        FROM comments c
        JOIN users u ON c.master_id = u.id
        WHERE c.request_id = ?
        ORDER BY c.created_at DESC
    ''', (request_id,))
    
    # Получаем список мастеров для формы назначения
    masters = query_db('''
        SELECT id, fio FROM users 
        WHERE type IN ('Мастер', 'admin')
        ORDER BY fio
    ''')
    
    # Получаем продления сроков (если есть)
    deadline_extensions = query_db('''
        SELECT de.*, u.fio as extended_by_fio
        FROM deadline_extensions de
        JOIN users u ON de.extended_by = u.id
        WHERE de.request_id = ?
        ORDER BY de.extended_at DESC
    ''', (request_id,))
    
    # Рассчитываем общее продление срока
    total_extension = sum(ext['extra_days'] for ext in deadline_extensions)
    
    return render_template('request_detail.html', 
                         request=request_data,
                         comments=comments,
                         masters=masters,
                         deadline_extensions=deadline_extensions,
                         total_extension=total_extension)

@app.route('/request/<int:request_id>/change-status', methods=('POST',))
@login_required
@role_required('Оператор', 'Мастер', 'admin', 'Менеджер', 'Менеджер по качеству')
def change_status(request_id):
    """
    Изменение статуса заявки.
    Разные пользователи могут менять статусы в зависимости от своих прав.
    """
    new_status = request.form.get('status', '').strip()
    
    # Проверяем валидность статуса
    valid_statuses = ['Новая заявка', 'В процессе ремонта', 'Ожидание запчастей', 'Готова к выдаче']
    if new_status not in valid_statuses:
        flash('Неверный статус.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Получаем текущую заявку
    request_data = query_db(
        'SELECT * FROM repair_requests WHERE id = ?', 
        (request_id,), 
        one=True
    )
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверка прав для мастера
    if g.user['type'] == 'Мастер':
        # Мастер может менять статус только своих заявок
        if request_data['master_id'] != g.user['id']:
            flash('Вы не можете менять статус этой заявки.', 'danger')
            return redirect(url_for('request_detail', request_id=request_id))
    
    # Если статус меняется на "Готова к выдаче", устанавливаем дату завершения
    completion_date = request_data['completion_date']
    if new_status == 'Готова к выдаче' and request_data['request_status'] != 'Готова к выдаче':
        completion_date = datetime.now().strftime('%Y-%m-%d')
    elif new_status != 'Готова к выдаче':
        completion_date = None
    
    # Обновляем статус в базе данных
    try:
        execute_db('''
            UPDATE repair_requests 
            SET request_status = ?, 
                completion_date = ?, 
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, completion_date, request_id))
        
        flash(f'Статус заявки изменен на "{new_status}"', 'success')
        
    except Exception as e:
        flash(f'Ошибка при изменении статуса: {str(e)}', 'danger')
    
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/assign-master', methods=('POST',))
@login_required
@role_required('Оператор', 'admin', 'Менеджер', 'Менеджер по качеству')
def assign_master(request_id):
    """
    Назначение мастера на заявку.
    Доступно операторам, менеджерам и администраторам.
    """
    master_id = request.form.get('master_id', '').strip()
    
    if not master_id:
        flash('Выберите мастера.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    try:
        master_id = int(master_id)
    except ValueError:
        flash('Неверный ID мастера.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Проверяем, существует ли мастер
    master = query_db(
        'SELECT * FROM users WHERE id = ? AND type IN ("Мастер", "admin")', 
        (master_id,), 
        one=True
    )
    
    if master is None:
        flash('Выбранный мастер не найден.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Назначаем мастера на заявку
    try:
        execute_db('''
            UPDATE repair_requests 
            SET master_id = ?, 
                request_status = 'В процессе ремонта',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (master_id, request_id))
        
        flash(f'Мастер {master["fio"]} назначен на заявку', 'success')
        
    except Exception as e:
        flash(f'Ошибка при назначении мастера: {str(e)}', 'danger')
    
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/update-parts', methods=('POST',))
@login_required
@role_required('Мастер', 'Оператор', 'admin', 'Менеджер', 'Менеджер по качеству')
def update_parts(request_id):
    """
    Обновление информации о запчастях.
    Мастер может указать, какие запчасти требуются или использовались.
    """
    repair_parts = request.form.get('repair_parts', '').strip()
    
    # Проверяем права мастера
    if g.user['type'] == 'Мастер':
        request_data = query_db(
            'SELECT * FROM repair_requests WHERE id = ?', 
            (request_id,), 
            one=True
        )
        
        if request_data and request_data['master_id'] != g.user['id']:
            flash('Вы не можете обновлять информацию о запчастях для этой заявки.', 'danger')
            return redirect(url_for('request_detail', request_id=request_id))
    
    # Обновляем информацию о запчастях
    try:
        execute_db('''
            UPDATE repair_requests 
            SET repair_parts = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (repair_parts, request_id))
        
        flash('Информация о запчастях обновлена', 'success')
        
    except Exception as e:
        flash(f'Ошибка при обновлении информации: {str(e)}', 'danger')
    
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/add-comment', methods=('POST',))
@login_required
@role_required('Мастер', 'Оператор', 'admin', 'Менеджер', 'Менеджер по качеству')
def add_comment(request_id):
    """
    Добавление комментария к заявке.
    Комментарии могут оставлять мастера, операторы и менеджеры.
    """
    message = request.form.get('message', '').strip()
    
    if not message:
        flash('Комментарий не может быть пустым.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Проверяем, что заявка существует
    request_data = query_db(
        'SELECT * FROM repair_requests WHERE id = ?', 
        (request_id,), 
        one=True
    )
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверка прав для мастера
    if g.user['type'] == 'Мастер':
        if request_data['master_id'] != g.user['id']:
            flash('Вы не можете добавлять комментарии к этой заявке.', 'danger')
            return redirect(url_for('request_detail', request_id=request_id))
    
    # Добавляем комментарий
    try:
        execute_db('''
            INSERT INTO comments (request_id, master_id, message)
            VALUES (?, ?, ?)
        ''', (request_id, g.user['id'], message))
        
        flash('Комментарий успешно добавлен!', 'success')
        
    except Exception as e:
        flash(f'Ошибка при добавлении комментария: {str(e)}', 'danger')
    
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/edit', methods=('GET', 'POST'))
@login_required
@role_required('Оператор', 'admin', 'Менеджер')
def edit_request(request_id):
    """
    Редактирование заявки.
    Доступно операторам и администраторам.
    """
    # Получаем заявку
    request_data = query_db('''
        SELECT r.*, uc.fio as client_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        WHERE r.id = ?
    ''', (request_id,), one=True)
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Получаем данные из формы
        home_tech_type = request.form.get('home_tech_type', '').strip()
        home_tech_model = request.form.get('home_tech_model', '').strip()
        problem_description = request.form.get('problem_description', '').strip()
        request_status = request.form.get('request_status', '').strip()
        master_id = request.form.get('master_id', '').strip() or None
        repair_parts = request.form.get('repair_parts', '').strip()
        
        # Проверяем обязательные поля
        if not home_tech_type or not home_tech_model or not problem_description:
            flash('Заполните все обязательные поля.', 'danger')
            return redirect(url_for('edit_request', request_id=request_id))
        
        # Если статус "Готова к выдаче" и был другим, устанавливаем дату завершения
        completion_date = request_data['completion_date']
        if request_status == 'Готова к выдаче' and request_data['request_status'] != 'Готова к выдаче':
            completion_date = datetime.now().strftime('%Y-%m-%d')
        elif request_status != 'Готова к выдаче':
            completion_date = None
        
        # Обновляем заявку
        try:
            execute_db('''
                UPDATE repair_requests 
                SET home_tech_type = ?,
                    home_tech_model = ?,
                    problem_description = ?,
                    request_status = ?,
                    master_id = ?,
                    repair_parts = ?,
                    completion_date = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (home_tech_type, home_tech_model, problem_description, 
                  request_status, master_id, repair_parts, completion_date, request_id))
            
            flash('Заявка успешно обновлена!', 'success')
            return redirect(url_for('request_detail', request_id=request_id))
            
        except Exception as e:
            flash(f'Ошибка при обновлении заявки: {str(e)}', 'danger')
    
    # GET запрос - показываем форму редактирования
    # Получаем список мастеров для выбора
    masters = query_db('''
        SELECT id, fio FROM users 
        WHERE type IN ('Мастер', 'admin')
        ORDER BY fio
    ''')
    
    # Получаем список клиентов (для оператора)
    clients = query_db('SELECT id, fio FROM users WHERE type = "Заказчик" ORDER BY fio')
    
    return render_template('request_edit.html', 
                         request=request_data,
                         masters=masters,
                         clients=clients)

# ==================== УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ====================

@app.route('/users')
@login_required
@role_required('Оператор', 'admin', 'Менеджер')
def users():
    """
    Список пользователей системы.
    Доступно операторам и администраторам.
    """
    users_list = query_db('SELECT * FROM users ORDER BY type, fio')
    return render_template('users.html', users=users_list)

@app.route('/user/create', methods=('GET', 'POST'))
@login_required
@role_required('admin', 'Менеджер')
def create_user():
    """
    Создание нового пользователя.
    Доступно только администраторам и менеджерам.
    """
    if request.method == 'POST':
        # Получаем данные из формы
        fio = request.form.get('fio', '').strip()
        phone = request.form.get('phone', '').strip()
        login = request.form.get('login', '').strip()
        password = request.form.get('password', '').strip()
        user_type = request.form.get('type', '').strip()
        
        # Проверяем обязательные поля
        if not all([fio, phone, login, password, user_type]):
            flash('Заполните все поля.', 'danger')
            return render_template('user_edit.html', user=None)
        
        # Проверяем, существует ли пользователь с таким логином
        existing_user = query_db(
            'SELECT id FROM users WHERE login = ?', 
            (login,), 
            one=True
        )
        
        if existing_user:
            flash('Пользователь с таким логином уже существует.', 'danger')
            return render_template('user_edit.html', user=None)
        
        # Создаем нового пользователя
        try:
            execute_db('''
                INSERT INTO users (fio, phone, login, password_hash, type)
                VALUES (?, ?, ?, ?, ?)
            ''', (fio, phone, login, hash_password(password), user_type))
            
            flash(f'Пользователь {fio} успешно создан!', 'success')
            return redirect(url_for('users'))
            
        except Exception as e:
            flash(f'Ошибка при создании пользователя: {str(e)}', 'danger')
            return render_template('user_edit.html', user=None)
    
    # GET запрос - показываем форму создания
    return render_template('user_edit.html', user=None)

@app.route('/user/<int:user_id>/edit', methods=('GET', 'POST'))
@login_required
@role_required('admin')
def edit_user(user_id):
    """
    Редактирование пользователя.
    Доступно только администраторам.
    """
    # Получаем пользователя
    user = query_db(
        'SELECT * FROM users WHERE id = ?', 
        (user_id,), 
        one=True
    )
    
    if user is None:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('users'))
    
    # Нельзя редактировать самого себя (для безопасности)
    if user['id'] == g.user['id']:
        flash('Вы не можете редактировать свой собственный профиль через эту форму.', 'warning')
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        # Получаем данные из формы
        fio = request.form.get('fio', '').strip()
        phone = request.form.get('phone', '').strip()
        login = request.form.get('login', '').strip()
        user_type = request.form.get('type', '').strip()
        password = request.form.get('password', '').strip()
        
        # Проверяем обязательные поля (кроме пароля)
        if not all([fio, phone, login, user_type]):
            flash('Заполните все обязательные поля.', 'danger')
            return render_template('user_edit.html', user=user)
        
        # Проверяем, не занят ли логин другим пользователем
        existing_user = query_db(
            'SELECT id FROM users WHERE login = ? AND id != ?', 
            (login, user_id), 
            one=True
        )
        
        if existing_user:
            flash('Пользователь с таким логином уже существует.', 'danger')
            return render_template('user_edit.html', user=user)
        
        # Обновляем пользователя
        try:
            if password:  # Если указан новый пароль
                execute_db('''
                    UPDATE users 
                    SET fio = ?, phone = ?, login = ?, type = ?, password_hash = ?
                    WHERE id = ?
                ''', (fio, phone, login, user_type, hash_password(password), user_id))
            else:  # Если пароль не меняется
                execute_db('''
                    UPDATE users 
                    SET fio = ?, phone = ?, login = ?, type = ?
                    WHERE id = ?
                ''', (fio, phone, login, user_type, user_id))
            
            flash(f'Пользователь {fio} успешно обновлен!', 'success')
            return redirect(url_for('users'))
            
        except Exception as e:
            flash(f'Ошибка при обновлении пользователя: {str(e)}', 'danger')
            return render_template('user_edit.html', user=user)
    
    # GET запрос - показываем форму редактирования
    return render_template('user_edit.html', user=user)

@app.route('/user/<int:user_id>/delete', methods=('POST',))
@login_required
@role_required('admin')
def delete_user(user_id):
    """
    Удаление пользователя.
    Доступно только администраторам.
    """
    # Нельзя удалить самого себя
    if user_id == g.user['id']:
        flash('Вы не можете удалить свой собственный аккаунт.', 'danger')
        return redirect(url_for('users'))
    
    # Получаем пользователя
    user = query_db(
        'SELECT * FROM users WHERE id = ?', 
        (user_id,), 
        one=True
    )
    
    if user is None:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('users'))
    
    # Удаляем пользователя
    try:
        execute_db('DELETE FROM users WHERE id = ?', (user_id,))
        flash(f'Пользователь {user["fio"]} успешно удален.', 'success')
    except Exception as e:
        flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    
    return redirect(url_for('users'))

# ==================== МАСТЕРА ====================

@app.route('/masters')
@login_required
@role_required('Оператор', 'admin', 'Менеджер', 'Менеджер по качеству')
def masters():
    """
    Список мастеров и статистика по их работе.
    """
    # Получаем мастеров с их статистикой
    masters_list = query_db('''
        SELECT u.*, 
               COUNT(r.id) as total_requests,
               SUM(CASE WHEN r.request_status = 'Готова к выдаче' THEN 1 ELSE 0 END) as completed_requests,
               SUM(CASE WHEN r.request_status = 'В процессе ремонта' THEN 1 ELSE 0 END) as in_progress_requests,
               SUM(CASE WHEN r.request_status = 'Ожидание запчастей' THEN 1 ELSE 0 END) as waiting_parts_requests
        FROM users u
        LEFT JOIN repair_requests r ON u.id = r.master_id
        WHERE u.type IN ('Мастер', 'admin')
        GROUP BY u.id
        ORDER BY u.fio
    ''')
    
    # Получаем заявки без мастера
    unassigned_requests = query_db('''
        SELECT COUNT(*) as count 
        FROM repair_requests 
        WHERE master_id IS NULL AND request_status = 'Новая заявка'
    ''', one=True)['count']
    
    # Получаем перегруженных мастеров (более 5 заявок в работе)
    overloaded_masters = query_db('''
        SELECT u.fio, COUNT(r.id) as active_count
        FROM users u
        JOIN repair_requests r ON u.id = r.master_id
        WHERE r.request_status IN ('В процессе ремонта', 'Ожидание запчастей')
        GROUP BY u.id
        HAVING active_count > 5
        ORDER BY active_count DESC
    ''')
    
    return render_template('masters.html', 
                         masters=masters_list,
                         unassigned_requests=unassigned_requests,
                         overloaded_masters=overloaded_masters)

# ==================== СТАТИСТИКА ====================

@app.route('/stats')
@login_required
@role_required('Оператор', 'admin', 'Менеджер', 'Менеджер по качеству')
def stats():
    """
    Статистика работы сервисного центра.
    """
    # 1. Общая статистика
    total_requests = query_db('SELECT COUNT(*) as count FROM repair_requests', one=True)['count']
    completed_requests = query_db(
        "SELECT COUNT(*) as count FROM repair_requests WHERE request_status = 'Готова к выдаче'", 
        one=True
    )['count']
    in_progress_requests = query_db(
        "SELECT COUNT(*) as count FROM repair_requests WHERE request_status = 'В процессе ремонта'", 
        one=True
    )['count']
    
    # 2. Среднее время выполнения заявок (в днях)
    avg_time_result = query_db('''
        SELECT AVG(julianday(completion_date) - julianday(start_date)) as avg_days
        FROM repair_requests 
        WHERE request_status = 'Готова к выдаче' AND completion_date IS NOT NULL
    ''', one=True)
    avg_days = avg_time_result['avg_days'] if avg_time_result and avg_time_result['avg_days'] else 0
    
    # 3. Статистика по типам техники
    equipment_stats = query_db('''
        SELECT home_tech_type, COUNT(*) as count,
               ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM repair_requests), 1) as percentage
        FROM repair_requests
        GROUP BY home_tech_type
        ORDER BY count DESC
    ''')
    
    # 4. Статистика по статусам
    status_stats = query_db('''
        SELECT request_status, COUNT(*) as count,
               ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM repair_requests), 1) as percentage
        FROM repair_requests
        GROUP BY request_status
        ORDER BY 
            CASE request_status
                WHEN 'Новая заявка' THEN 1
                WHEN 'В процессе ремонта' THEN 2
                WHEN 'Ожидание запчастей' THEN 3
                WHEN 'Готова к выдаче' THEN 4
                ELSE 5
            END
    ''')
    
    # 5. Статистика по месяцам
    monthly_stats = query_db('''
        SELECT strftime('%Y-%m', start_date) as month,
               COUNT(*) as count,
               SUM(CASE WHEN request_status = 'Готова к выдаче' THEN 1 ELSE 0 END) as completed
        FROM repair_requests
        GROUP BY strftime('%Y-%m', start_date)
        ORDER BY month DESC
        LIMIT 12
    ''')
    
    # 6. Топ-5 самых частых проблем
    common_problems = query_db('''
        SELECT problem_description, COUNT(*) as count
        FROM repair_requests
        GROUP BY problem_description
        ORDER BY count DESC
        LIMIT 5
    ''')
    
    return render_template('stats.html',
                         total_requests=total_requests,
                         completed_requests=completed_requests,
                         in_progress_requests=in_progress_requests,
                         avg_days=round(avg_days, 1),
                         equipment_stats=equipment_stats,
                         status_stats=status_stats,
                         monthly_stats=monthly_stats,
                         common_problems=common_problems)

# ==================== МЕНЕДЖЕР ПО КАЧЕСТВУ ====================

@app.route('/overdue-requests')
@login_required
@role_required('Менеджер по качеству', 'admin', 'Менеджер')
def overdue_requests():
    """
    Просроченные заявки (в работе более 7 дней).
    """
    overdue = query_db('''
        SELECT r.*, uc.fio as client_fio, um.fio as master_fio,
               julianday('now') - julianday(r.start_date) as days_passed
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        LEFT JOIN users um ON r.master_id = um.id
        WHERE r.request_status IN ('В процессе ремонта', 'Ожидание запчастей')
        AND julianday('now') - julianday(r.start_date) > 7
        ORDER BY days_passed DESC
    ''')
    
    return render_template('overdue_requests.html', requests=overdue)

@app.route('/problem-requests')
@login_required
@role_required('Менеджер по качеству', 'admin', 'Менеджер', 'Мастер')
def problem_requests():
    """
    Проблемные заявки (требующие консультации или помощи).
    """
    problems = query_db('''
        SELECT r.*, uc.fio as client_fio, um.fio as master_fio,
               (SELECT COUNT(*) FROM comments c WHERE c.request_id = r.id) as comment_count,
               julianday('now') - julianday(r.start_date) as days_passed
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        LEFT JOIN users um ON r.master_id = um.id
        WHERE r.request_status = 'Ожидание запчастей'
           OR r.id IN (
               SELECT DISTINCT request_id 
               FROM comments 
               WHERE message LIKE '%проблем%' 
                  OR message LIKE '%сложн%' 
                  OR message LIKE '%не могу%'
                  OR message LIKE '%помощ%'
                  OR message LIKE '%консульта%'
           )
        ORDER BY r.start_date DESC
    ''')
    
    return render_template('problem_requests.html', requests=problems)

@app.route('/request/<int:request_id>/extend-deadline', methods=('GET', 'POST'))
@login_required
@role_required('Менеджер по качеству', 'admin')
def extend_deadline(request_id):
    """
    Продление срока выполнения заявки.
    Функционал менеджера по качеству.
    """
    # Получаем информацию о заявке
    request_data = query_db('''
        SELECT r.*, uc.fio as client_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        WHERE r.id = ?
    ''', (request_id,), one=True)
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Получаем данные из формы
        extra_days = request.form.get('extra_days', '').strip()
        reason = request.form.get('reason', '').strip()
        
        # Проверяем ввод
        if not extra_days or not extra_days.isdigit():
            flash('Укажите корректное количество дней.', 'danger')
            return render_template('extend_deadline.html', request=request_data)
        
        if not reason:
            flash('Укажите причину продления.', 'danger')
            return render_template('extend_deadline.html', request=request_data)
        
        extra_days = int(extra_days)
        
        # Записываем продление в базу данных
        try:
            # Добавляем запись о продлении
            execute_db('''
                INSERT INTO deadline_extensions (request_id, extended_by, extra_days, reason)
                VALUES (?, ?, ?, ?)
            ''', (request_id, g.user['id'], extra_days, reason))
            
            # Добавляем комментарий о продлении
            execute_db('''
                INSERT INTO comments (request_id, master_id, message)
                VALUES (?, ?, ?)
            ''', (request_id, g.user['id'], 
                  f'Срок выполнения продлен на {extra_days} дней. Причина: {reason}'))
            
            flash(f'Срок заявки №{request_id} продлен на {extra_days} дней', 'success')
            return redirect(url_for('request_detail', request_id=request_id))
            
        except Exception as e:
            flash(f'Ошибка при продлении срока: {str(e)}', 'danger')
            return render_template('extend_deadline.html', request=request_data)
    
    # GET запрос - показываем форму
    return render_template('extend_deadline.html', request=request_data)

@app.route('/request/<int:request_id>/add-master-help', methods=('POST',))
@login_required
@role_required('Менеджер по качеству', 'admin', 'Мастер')
def add_master_help(request_id):
    """
    Привлечение дополнительного мастера для помощи.
    Мастер может запросить помощь, менеджер по качеству может назначить.
    """
    master_id = request.form.get('master_id', '').strip()
    reason = request.form.get('reason', '').strip()
    
    if not master_id:
        flash('Выберите мастера.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    try:
        master_id = int(master_id)
    except ValueError:
        flash('Неверный ID мастера.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Проверяем мастера
    master = query_db(
        'SELECT * FROM users WHERE id = ? AND type IN ("Мастер", "admin")', 
        (master_id,), 
        one=True
    )
    
    if master is None:
        flash('Мастер не найден.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Создаем сообщение о привлечении мастера
    message = f'Привлечен дополнительный мастер для консультации: {master["fio"]}'
    if reason:
        message += f'. Причина: {reason}'
    
    if g.user['type'] == 'Мастер':
        message += f' (запросил: {g.user["fio"]})'
    
    # Добавляем комментарий
    try:
        execute_db('''
            INSERT INTO comments (request_id, master_id, message)
            VALUES (?, ?, ?)
        ''', (request_id, g.user['id'], message))
        
        flash(f'Мастер {master["fio"]} привлечен к консультации', 'success')
        
    except Exception as e:
        flash(f'Ошибка при привлечении мастера: {str(e)}', 'danger')
    
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/quality-stats')
@login_required
@role_required('Менеджер по качеству', 'admin', 'Менеджер')
def quality_stats():
    """
    Статистика качества работы.
    """
    # Среднее время выполнения
    avg_time = query_db('''
        SELECT AVG(julianday(completion_date) - julianday(start_date)) as avg_days
        FROM repair_requests 
        WHERE request_status = 'Готова к выдаче' AND completion_date IS NOT NULL
    ''', one=True)['avg_days'] or 0
    
    # Количество просроченных заявок
    overdue_count = query_db('''
        SELECT COUNT(*) as count
        FROM repair_requests
        WHERE request_status IN ('В процессе ремонта', 'Ожидание запчастей')
        AND julianday('now') - julianday(start_date) > 7
    ''', one=True)['count']
    
    # Количество заявок с продлением срока
    extended_count = query_db('''
        SELECT COUNT(DISTINCT request_id) as count
        FROM deadline_extensions
    ''', one=True)['count']
    
    # Количество заявок с проблемами
    problem_count = query_db('''
        SELECT COUNT(DISTINCT r.id) as count
        FROM repair_requests r
        LEFT JOIN comments c ON r.id = c.request_id
        WHERE r.request_status = 'Ожидание запчастей'
           OR c.message LIKE '%проблем%' 
           OR c.message LIKE '%сложн%'
           OR c.message LIKE '%помощ%'
    ''', one=True)['count']
    
    # Статистика по мастерам (кто чаще просит помощь)
    masters_needing_help = query_db('''
        SELECT u.fio, COUNT(DISTINCT c.request_id) as help_requests
        FROM comments c
        JOIN users u ON c.master_id = u.id
        WHERE c.message LIKE '%помощ%' OR c.message LIKE '%консульта%'
        GROUP BY u.id
        ORDER BY help_requests DESC
        LIMIT 5
    ''')
    
    return render_template('quality_stats.html',
                         avg_days=round(avg_time, 1),
                         overdue_count=overdue_count,
                         extended_count=extended_count,
                         problem_count=problem_count,
                         masters_needing_help=masters_needing_help)

# ==================== QR-КОДЫ ДЛЯ ОТЗЫВОВ ====================

@app.route('/request/<int:request_id>/feedback-qr')
@login_required
@role_required('Оператор', 'admin', 'Менеджер по качеству')
def generate_feedback_qr(request_id):
    """
    Генерация QR-кода для оценки работы.
    Ссылка ведет на Google Forms с опросом.
    """
    # Базовая ссылка на Google Forms из ТЗ
    base_url = "https://docs.google.com/forms/d/e/1FAIpQLSdhZcExx6LSIXxk0ub55mSu-WIh23WYdGG9HY5EZhLDo7P8eA/viewform?usp=sf_link"
    
    # Добавляем параметры для отслеживания
    feedback_url = f"{base_url}&entry.1234567890={request_id}"
    
    # Создаем QR-код
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(feedback_url)
    qr.make(fit=True)
    
    # Создаем изображение
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Сохраняем в буфер
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return send_file(buf, 
                     mimetype='image/png', 
                     as_attachment=False, 
                     download_name=f'feedback_qr_{request_id}.png')

@app.route('/request/<int:request_id>/feedback')
@login_required
def feedback_page(request_id):
    """
    Страница с QR-кодом для оценки работы.
    """
    # Получаем информацию о заявке
    request_data = query_db('''
        SELECT r.*, uc.fio as client_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        WHERE r.id = ?
    ''', (request_id,), one=True)
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверка прав доступа
    if g.user['type'] == 'Заказчик' and request_data['client_id'] != g.user['id']:
        flash('У вас нет доступа к этой заявке.', 'danger')
        return redirect(url_for('index'))
    
    # Ссылка на форму
    feedback_url = "https://docs.google.com/forms/d/e/1FAIpQLSdhZcExx6LSIXxk0ub55mSu-WIh23WYdGG9HY5EZhLDo7P8eA/viewform?usp=sf_link"
    
    return render_template('feedback.html', 
                         request=request_data, 
                         feedback_url=feedback_url)

# ==================== API ДЛЯ ФРОНТЕНДА ====================

@app.route('/api/requests')
@login_required
def api_requests():
    """
    API для получения списка заявок.
    Возвращает данные в формате JSON.
    """
    # Аналогично функции index(), но возвращает JSON
    if g.user['type'] == 'Заказчик':
        requests = query_db('''
            SELECT r.*, u.fio as master_fio
            FROM repair_requests r
            LEFT JOIN users u ON r.master_id = u.id
            WHERE r.client_id = ?
            ORDER BY r.start_date DESC
        ''', (g.user['id'],))
    elif g.user['type'] == 'Мастер':
        requests = query_db('''
            SELECT r.*, uc.fio as client_fio, um.fio as master_fio
            FROM repair_requests r
            LEFT JOIN users uc ON r.client_id = uc.id
            LEFT JOIN users um ON r.master_id = um.id
            WHERE r.master_id = ?
            ORDER BY r.start_date DESC
        ''', (g.user['id'],))
    else:
        requests = query_db('''
            SELECT r.*, uc.fio as client_fio, um.fio as master_fio
            FROM repair_requests r
            LEFT JOIN users uc ON r.client_id = uc.id
            LEFT JOIN users um ON r.master_id = um.id
            ORDER BY r.start_date DESC
        ''')
    
    # Конвертируем в список словарей
    requests_list = []
    for req in requests:
        req_dict = dict(req)
        # Конвертируем даты в строки
        if req_dict.get('start_date'):
            req_dict['start_date'] = str(req_dict['start_date'])
        if req_dict.get('completion_date'):
            req_dict['completion_date'] = str(req_dict['completion_date'])
        requests_list.append(req_dict)
    
    return jsonify(requests_list)

@app.route('/api/stats/summary')
@login_required
@role_required('Оператор', 'admin', 'Менеджер', 'Менеджер по качеству')
def api_stats_summary():
    """
    API для получения сводной статистики.
    """
    total = query_db('SELECT COUNT(*) as count FROM repair_requests', one=True)['count']
    completed = query_db(
        "SELECT COUNT(*) as count FROM repair_requests WHERE request_status = 'Готова к выдаче'", 
        one=True
    )['count']
    in_progress = query_db(
        "SELECT COUNT(*) as count FROM repair_requests WHERE request_status = 'В процессе ремонта'", 
        one=True
    )['count']
    
    return jsonify({
        'total': total,
        'completed': completed,
        'in_progress': in_progress,
        'completion_rate': round(completed / total * 100, 1) if total > 0 else 0
    })

# ==================== ОБРАБОТКА ОШИБОК ====================

@app.errorhandler(404)
def page_not_found(e):
    """
    Обработка ошибки 404 - страница не найдена.
    """
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """
    Обработка ошибки 500 - внутренняя ошибка сервера.
    """
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    """
    Обработка ошибки 403 - доступ запрещен.
    """
    flash('Доступ запрещен. У вас недостаточно прав.', 'danger')
    return redirect(url_for('index'))

# ==================== ИНИЦИАЛИЗАЦИЯ И ЗАПУСК ====================

def import_initial_data():
    """
    Импорт начальных тестовых данных из ТЗ.
    Выполняется при первом запуске приложения.
    """
    db = get_db()
    
    # Проверяем, есть ли уже пользователи
    user_count = query_db('SELECT COUNT(*) as count FROM users', one=True)['count']
    if user_count > 0:
        print("✅ В базе данных уже есть пользователи, пропускаем импорт")
        return
    
    print("🔄 Импортирую тестовые данные...")
    
    # Хэшируем пароли
    def hash_pw(password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    # Импортируем пользователей из ТЗ
    users_data = [
        (1, 'Трубин Никита Юрьевич', '89210563128', 'kasoo', hash_pw('root'), 'admin'),
        (2, 'Мурашов Андрей Юрьевич', '89535078985', 'murashov123', hash_pw('qwerty'), 'Мастер'),
        (3, 'Степанов Андрей Викторович', '89210673849', 'test1', hash_pw('test1'), 'Мастер'),
        (4, 'Перина Анастасия Денисовна', '89990563748', 'perinaAD', hash_pw('250519'), 'Оператор'),
        (5, 'Мажитова Ксения Сергеевна', '89994563847', 'krutiha1234567', hash_pw('1234567890'), 'Оператор'),
        (6, 'Семенова Ясмина Марковна', '89994563847', 'login1', hash_pw('pass1'), 'Мастер'),
        (7, 'Баранова Эмилия Марковна', '89994563841', 'login2', hash_pw('pass2'), 'Заказчик'),
        (8, 'Егорова Алиса Платоновна', '89994563842', 'login3', hash_pw('pass3'), 'Заказчик'),
        (9, 'Титов Максим Иванович', '89994563843', 'login4', hash_pw('pass4'), 'Заказчик'),
        (10, 'Иванов Марк Максимович', '89994563844', 'login5', hash_pw('pass5'), 'Мастер'),
        (11, 'Менеджер по качеству', '89990000000', 'quality', hash_pw('quality123'), 'Менеджер по качеству'),
        (12, 'Менеджер', '89991112233', 'manager', hash_pw('manager123'), 'Менеджер')
    ]
    
    for user in users_data:
        try:
            execute_db('''
                INSERT INTO users (id, fio, phone, login, password_hash, type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', user)
            print(f"  👤 Создан пользователь: {user[1]} ({user[5]})")
        except Exception as e:
            print(f"  ⚠️ Ошибка при создании пользователя {user[1]}: {e}")
    
    # Импортируем заявки из ТЗ
    try:
        test_requests = [
            (1, '2023-06-06', 'Фен', 'Ладомир ТА112 белый', 'Перестал работать', 'В процессе ремонта', None, '', 2, 7),
            (2, '2023-05-05', 'Тостер', 'Redmond RT-437 черный', 'Перестал работать', 'В процессе ремонта', None, '', 3, 7),
            (3, '2022-07-07', 'Холодильник', 'Indesit DS 316 W белый', 'Не морозит одна из камер холодильника', 'Готова к выдаче', '2023-01-01', '', 2, 8),
            (4, '2023-08-02', 'Стиральная машина', 'DEXP WM-F610NTMA/WW белый', 'Перестали работать многие режимы стирки', 'Новая заявка', None, '', None, 8),
            (5, '2023-08-02', 'Мультиварка', 'Redmond RMC-M95 черный', 'Перестала включаться', 'Новая заявка', None, '', None, 9),
            (6, '2023-08-02', 'Фен', 'Ладомир ТА113 чёрный', 'Перестал работать', 'Готова к выдаче', '2023-08-03', '', 2, 7),
            (7, '2023-07-09', 'Холодильник', 'Indesit DS 314 W серый', 'Гудит, но не замораживает', 'Готова к выдаче', '2023-08-03', 'Мотор обдува морозильной камеры холодильника', 2, 8),
            (8, '2023-09-01', 'Пылесос', 'Samsung VC18M31A0HP/EV', 'Слабый поток воздуха', 'В процессе ремонта', None, 'Фильтр, мешок для пыли', 6, 7),
            (9, '2023-09-05', 'Микроволновая печь', 'LG MS-2042DB', 'Не греет, но светится и крутится', 'Ожидание запчастей', None, 'Магнетрон', 10, 8),
            (10, '2023-09-10', 'Посудомоечная машина', 'Bosch SMS46MI01R', 'Не сливает воду', 'Новая заявка', None, '', None, 9)
        ]
        
        for req in test_requests:
            execute_db('''
                INSERT INTO repair_requests (id, start_date, home_tech_type, home_tech_model, problem_description, request_status, completion_date, repair_parts, master_id, client_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', req)
            print(f"  📝 Создана заявка #{req[0]}: {req[2]} {req[3]}")
        
        # Импортируем комментарии из ТЗ
        test_comments = [
            (1, 'Интересная поломка', 2, 1),
            (2, 'Очень странно, будем разбираться!', 3, 2),
            (3, 'Скорее всего потребуется мотор обдува!', 2, 7),
            (4, 'Интересная проблема', 2, 1),
            (5, 'Очень странно, будем разбираться!', 3, 6),
            (6, 'Заказал запчасти, ждем доставку', 10, 9),
            (7, 'Проверил, нужна замена фильтра', 6, 8),
            (8, 'Готов к выдаче, клиент уведомлен', 2, 3)
        ]
        
        for comment in test_comments:
            execute_db('''
                INSERT INTO comments (id, message, master_id, request_id)
                VALUES (?, ?, ?, ?)
            ''', comment)
            print(f"  💬 Добавлен комментарий к заявке #{comment[3]}")
        
        # Добавляем несколько продлений сроков
        extensions = [
            (1, 9, 11, 5, 'Ожидание доставки запчастей из-за логистических проблем'),
            (2, 1, 11, 3, 'Сложный ремонт, требуется дополнительное время')
        ]
        
        for ext in extensions:
            execute_db('''
                INSERT INTO deadline_extensions (id, request_id, extended_by, extra_days, reason)
                VALUES (?, ?, ?, ?, ?)
            ''', ext)
            print(f"  📅 Добавлено продление срока для заявки #{ext[1]}")
        
        print("✅ Все тестовые данные успешно импортированы!")
        
    except Exception as e:
        print(f"❌ Ошибка при импорте данных: {e}")

if __name__ == '__main__':
    # Импортируем начальные данные при первом запуске
    with app.app_context():
        import_initial_data()
    
    # Выводим информацию для запуска
    print("=" * 70)
    print("🔧 СИСТЕМА УЧЕТА ЗАЯВОК НА РЕМОНТ БЫТОВОЙ ТЕХНИКИ")
    print("=" * 70)
    print("✅ База данных инициализирована")
    print("✅ Тестовые данные загружены")
    print("\n👥 ТЕСТОВЫЕ УЧЕТНЫЕ ЗАПИСИ:")
    print("  👑 АДМИНИСТРАТОР (полный доступ):           kasoo / root")
    print("  👩‍💼 ОПЕРАТОР (управление заявками):         perinaAD / 250519")
    print("  👨‍🔧 МАСТЕР (ремонт, комментарии):           murashov123 / qwerty")
    print("  👨‍🔧 МАСТЕР 2:                              test1 / test1")
    print("  👤 ЗАКАЗЧИК (создание/просмотр заявок):     login2 / pass2")
    print("  📊 МЕНЕДЖЕР ПО КАЧЕСТВУ (продление сроков): quality / quality123")
    print("  👨‍💼 МЕНЕДЖЕР:                               manager / manager123")
    print("\n🌐 Веб-интерфейс доступен по адресу: http://localhost:5000")
    print("📱 API доступен по адресу: http://localhost:5000/api/requests")
    print("=" * 70)
    print("\n🚀 Запуск сервера... (Ctrl+C для остановки)")
    print("-" * 70)
    
    # Запускаем сервер
    app.run(
        debug=True, 
        port=5000, 
        host='0.0.0.0',
        use_reloader=True
    )