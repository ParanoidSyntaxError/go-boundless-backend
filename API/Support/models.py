from API.extensions import db
from datetime import datetime, timezone

class SupportModel(db.Model):
    __tablename__ = "support"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=True)
    enquiry_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    message = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), nullable=False)
    