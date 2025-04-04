# utils.py
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app

serializer = URLSafeTimedSerializer("your-secret-key")

def generate_reset_token(user):
    return serializer.dumps(user.id, salt="password-reset-salt")

def verify_reset_token(token, expiration=3600):
    try:
        user_id = serializer.loads(token, salt="password-reset-salt", max_age=expiration)
        from models import User
        with current_app.app_context():
            return User.query.get(user_id)
    except:
        return None