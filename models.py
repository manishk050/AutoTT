# models.py
from database import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    department = db.Column(db.String(64), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LeaveRequest(db.Model):
    __tablename__ = 'leave_request'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    substitute_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.String(10), nullable=False)
    session = db.Column(db.Integer, nullable=False)
    teacher = db.relationship('User', foreign_keys=[teacher_id], backref='leaves_taken')
    substitute = db.relationship('User', foreign_keys=[substitute_id], backref='leaves_substituted')

class Timetable(db.Model):
    __tablename__ = 'timetable'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.String(10), nullable=False)
    session = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    substitute_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    teacher = db.relationship('User', foreign_keys=[teacher_id], backref='timetables')
    substitute = db.relationship('User', foreign_keys=[substitute_id])