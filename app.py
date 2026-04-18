from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, AuditResult, init_db
from functools import wraps
from datetime import datetime, date
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkeyforaudit'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///audit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Инициализация БД при первом запуске
with app.app_context():
    if not os.path.exists('instance/audit.db'):
        init_db(app)

# Декораторы для проверки ролей
def role_required(min_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role == 'Admin':
                return f(*args, **kwargs)
            roles = ['L1', 'L2', 'L3']
            if roles.index(current_user.role) >= roles.index(min_role):
                return f(*args, **kwargs)
            flash('У вас недостаточно прав для этого действия.', 'danger')
            return redirect(url_for('index'))
        return decorated_function
    return decorator

# Авторизация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()  # убираем пробелы
        password = request.form['password']
        
        # Ищем пользователя в базе
        user = User.query.filter_by(username=username).first()
        
        if user:
            from werkzeug.security import check_password_hash
            # Проверяем пароль через хеш
            if check_password_hash(user.password_hash, password):
                login_user(user)
                flash(f'Добро пожаловать, {user.full_name}!', 'success')
                return redirect(url_for('index'))
        
        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Основной интерфейс
@app.route('/')
@login_required
def index():
    query = AuditResult.query
    
    # Фильтры
    crit = request.args.get('criticality')
    stat = request.args.get('status')
    sys = request.args.get('system')
    resp = request.args.get('responsible')
    
    if crit: query = query.filter_by(criticality=crit)
    if stat: query = query.filter_by(status=stat)
    if sys: query = query.filter(AuditResult.system.like(f'%{sys}%'))
    if resp: query = query.filter_by(responsible_id=resp)
    
    # Сортировка
    sort = request.args.get('sort', 'detection_date')
    order = request.args.get('order', 'desc')
    if sort == 'risk_score':
        query = query.order_by(AuditResult.risk_score.desc() if order == 'desc' else AuditResult.risk_score.asc())
    else:
        query = query.order_by(AuditResult.detection_date.desc())
        
    page = request.args.get('page', 1, type=int)
    pagination = query.paginate(page=page, per_page=10)
    
    # Данные для фильтров
    systems = db.session.query(AuditResult.system).distinct().all()
    users = User.query.filter(User.role.in_(['L1', 'L2', 'L3'])).all()
    
    today = date.today()
    
    # Убираем page из аргументов для ссылок пагинации
    args_without_page = {k: v for k, v in request.args.items() if k != 'page'}
    
    return render_template('index.html', 
                         results=pagination.items, 
                         pagination=pagination,
                         systems=systems,
                         users=users,
                         today=today,
                         args_without_page=args_without_page,
                         current_filters=request.args)

@app.route('/card/<int:id>', methods=['GET', 'POST'])
@login_required
def card(id):
    result = AuditResult.query.get_or_404(id)
    if request.method == 'POST':
        # L2 и выше могут менять статус и комментарии
        if current_user.role in ['L2', 'L3', 'Admin']:
            new_status = request.form.get('status')
            new_comment = request.form.get('comment')
            if new_status:
                result.status = new_status
            if new_comment:
                if result.comments:
                    result.comments += f"\n[{datetime.now().strftime('%d.%m.%Y %H:%M')}] {current_user.full_name}: {new_comment}"
                else:
                    result.comments = f"[{datetime.now().strftime('%d.%m.%Y %H:%M')}] {current_user.full_name}: {new_comment}"
        
        # L3 и Admin могут менять критичность и финальное решение
        if current_user.role in ['L3', 'Admin']:
            new_crit = request.form.get('criticality')
            new_decision = request.form.get('final_decision')
            if new_crit:
                result.criticality = new_crit
            if new_decision:
                result.final_decision = new_decision
                
        db.session.commit()
        flash('Изменения сохранены', 'success')
        return redirect(url_for('card', id=id))
        
    return render_template('card.html', result=result)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/dashboard_data')
@login_required
def dashboard_data():
    # Данные для графиков
    from sqlalchemy import func
    crit_data = db.session.query(AuditResult.criticality, func.count(AuditResult.id)).group_by(AuditResult.criticality).all()
    status_data = db.session.query(AuditResult.status, func.count(AuditResult.id)).group_by(AuditResult.status).all()
    sys_data = db.session.query(AuditResult.system, func.count(AuditResult.id)).group_by(AuditResult.system).all()
    
    # Динамика по месяцам
    monthly = db.session.query(
        func.strftime('%Y-%m', AuditResult.detection_date).label('month'),
        func.count(AuditResult.id)
    ).group_by('month').order_by('month').limit(6).all()
    
    return jsonify({
        'criticality': {k: v for k, v in crit_data},
        'status': {k: v for k, v in status_data},
        'systems': {k: v for k, v in sys_data},
        'monthly': {k: v for k, v in monthly}
    })

@app.route('/calculators')
@login_required
def calculators():
    return render_template('calculators.html')

# Страница админа (управление юзерами)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'Admin':
        flash('Доступ запрещен. Требуются права администратора.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/add', methods=['POST'])
@login_required
def admin_add_user():
    if current_user.role != 'Admin':
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('index'))
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    full_name = request.form.get('full_name', '').strip()
    role = request.form.get('role')
    
    # Валидация
    errors = []
    if not username:
        errors.append('Логин не может быть пустым')
    if ' ' in username:
        errors.append('Логин не должен содержать пробелы')
    if len(username) < 3:
        errors.append('Логин должен быть не менее 3 символов')
    if not password:
        errors.append('Пароль не может быть пустым')
    if len(password) < 3:
        errors.append('Пароль должен быть не менее 3 символов')
    if not full_name:
        errors.append('Полное имя не может быть пустым')
    
    # Проверка на существующего пользователя
    existing = User.query.filter_by(username=username).first()
    if existing:
        errors.append(f'Пользователь {username} уже существует!')
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('admin_users'))
    
    from werkzeug.security import generate_password_hash
    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        full_name=full_name,
        role=role
    )
    
    db.session.add(new_user)
    db.session.commit()
    flash(f'Пользователь {username} успешно создан!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:user_id>')
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'Admin':
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # Нельзя удалить самого себя
    if user.id == current_user.id:
        flash('Нельзя удалить собственную учетную запись!', 'danger')
        return redirect(url_for('admin_users'))
    
    # Проверка, есть ли у пользователя назначенные аудиты
    has_audits = AuditResult.query.filter_by(responsible_id=user_id).first()
    if has_audits:
        flash(f'Нельзя удалить пользователя {user.username}, так как за ним закреплены аудиты!', 'warning')
        return redirect(url_for('admin_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'Пользователь {username} удален!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/edit/<int:user_id>', methods=['POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'Admin':
        flash('Доступ запрещен.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    user.full_name = request.form.get('full_name')
    user.role = request.form.get('role')
    
    new_password = request.form.get('password')
    if new_password:
        from werkzeug.security import generate_password_hash
        user.password_hash = generate_password_hash(new_password)
    
    db.session.commit()
    flash(f'Данные пользователя {user.username} обновлены!', 'success')
    return redirect(url_for('admin_users'))

if __name__ == '__main__':
    app.run(debug=True)