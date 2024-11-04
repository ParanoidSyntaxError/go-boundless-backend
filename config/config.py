import os
from urllib.parse import quote_plus
from datetime import timedelta

class Config:
    # DB_USERNAME = os.getenv('DATABASE_USERNAME')
    # DB_PASSWORD = os.getenv('DATABASE_PASSWORD')
    # DB_HOST = os.getenv('DATABASE_HOST')
    # DB_PORT = os.getenv('DATABASE_PORT')
    # DB_NAME = os.getenv('DATABASE_NAME')
    FRONTEND_URL = os.getenv('FRONTEND_URL')
    MAILGUN_API = os.getenv('MAILGUN_API_KEY')
    EMAIL_FROM = os.getenv('EMAIL_FROM')
    CLIENT_ID = os.getenv("DENT_CLIENT_ID") 
    CLIENT_SECRET = os.getenv("DENT_CLIENT_SECRET")

    # encoded_username = quote_plus(DB_USERNAME)
    # encoded_password = quote_plus(DB_PASSWORD)


    # SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{encoded_username}:{encoded_password}@{DB_HOST}:{DB_PORT}/portal"
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    STRIPE_PRIVATE_KEY=os.getenv("STRIPE_PRIVATE_KEY")
    STRIPE_ENDPOINT_SECRET=os.getenv("STRIPE_ENDPOINT_SECRET")
    SUPPORT_TEAM_EMAILS = os.getenv("SALES_TEAM_EMAILS")
