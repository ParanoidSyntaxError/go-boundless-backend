from API.extensions import db
from datetime import datetime, timezone 

class UserModel(db.Model):
    __tablename__ = "users" 

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dent_uid = db.Column(db.Integer, unique=True, nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    birthdate = db.Column(db.Date, nullable=True)
    currency = db.Column(db.String(10), nullable=False, default="USD")
    language = db.Column(db.String(50), nullable=False, default="English")
    marketing_emails = db.Column(db.Boolean, nullable=False, default=False)
    is_new_customer = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(80), default="user")
    first_name = db.Column(db.String(255), nullable=False)
    country = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(4), nullable=True)
    verification_code_expiry = db.Column(db.DateTime, nullable=True)
    reset_password_token = db.Column(db.String(36), nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
