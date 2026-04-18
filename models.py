from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import random

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Admin, L1, L2, L3
    full_name = db.Column(db.String(100))

class AuditResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_name = db.Column(db.String(200))
    system = db.Column(db.String(100))
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    criticality = db.Column(db.String(20))  # Low, Medium, High, Critical
    status = db.Column(db.String(20))       # Open, In Progress, Resolved, Closed
    responsible_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    responsible = db.relationship('User', foreign_keys=[responsible_id])
    detection_date = db.Column(db.Date)
    due_date = db.Column(db.Date)
    risk_score = db.Column(db.Integer)
    comments = db.Column(db.Text, default="")
    final_decision = db.Column(db.String(200), default="")

def init_db(app):
    with app.app_context():
        db.drop_all()
        db.create_all()
        
        # Создание пользователей
        users = [
            User(username='admin', password_hash=generate_password_hash('admin'), role='Admin', full_name='Иван Админов'),
            User(username='l1_user', password_hash=generate_password_hash('l1'), role='L1', full_name='Петр Аналитик 1'),
            User(username='l2_user', password_hash=generate_password_hash('l2'), role='L2', full_name='Сергей Аналитик 2'),
            User(username='l3_user', password_hash=generate_password_hash('l3'), role='L3', full_name='Анна Эксперт'),
            User(username='l2_second', password_hash=generate_password_hash('l2'), role='L2', full_name='Елена Аналитик L2'),
        ]
        for u in users:
            db.session.add(u)
        
        db.session.commit()
        
        # Создание тестовых результатов аудита
        systems = ['Core Banking', 'Internet Bank', 'Mobile App', 'Payment Gateway', 'ATM Controller']
        categories = ['Конфигурация', 'Управление доступом', 'Логирование', 'Шифрование', 'Сетевая безопасность']
        statuses = ['Open', 'In Progress', 'Resolved', 'Closed']
        crits = ['Low', 'Medium', 'High', 'Critical']
        analysts = User.query.filter(User.role.in_(['L1', 'L2', 'L3'])).all()
        
        for i in range(25):
            det_date = datetime.now().date() - timedelta(days=random.randint(1, 60))
            due_days = random.randint(5, 30)
            res = AuditResult(
                audit_name=f"Аудит {random.choice(['PCI DSS', 'ГОСТ 57580', 'СТО БР ИББС', 'GDPR'])} 2026",
                system=random.choice(systems),
                category=random.choice(categories),
                description=f"Обнаружено нарушение: {random.choice(['Слабый пароль', 'Отсутствие логов', 'Открытый порт', 'Устаревшая версия ПО', 'Нет MFA'])}",
                criticality=random.choice(crits),
                status=random.choice(statuses),
                responsible_id=random.choice(analysts).id,
                detection_date=det_date,
                due_date=det_date + timedelta(days=due_days),
                risk_score=random.randint(1, 100),
                comments="Начато расследование. Требуется уточнение у администратора системы." if i % 3 == 0 else ""
            )
            db.session.add(res)
            
        db.session.commit()
        print("База данных создана и заполнена тестовыми данными.")