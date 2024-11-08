from API.extensions import db
from datetime import datetime, timezone

class SimModel(db.Model):
    __tablename__ = 'sims'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    activation_code = db.Column(db.String(255), nullable=False)
    installation_url = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(50), default='NOT ACTIVATED', nullable=False)
    iccid = db.Column(db.String(50), unique=True, nullable=True)
    imsi = db.Column(db.String(50), unique=True, nullable=True)
    eid = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('UserModel', backref=db.backref('activations', lazy=True))
