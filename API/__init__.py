import logging
import os

from flask import Flask, jsonify
from flask_cors import CORS
from flask_smorest import Api
from passlib.hash import pbkdf2_sha256
from blocklist import BLOCKLIST
from dotenv import load_dotenv

from API.extensions import db, jwt, limiter 
from API.Auth import UsersBlueprint, UserModel
from API.Store import StoreBlueprint
from API.Support import SupportBlueprint

load_dotenv()

def create_flask_app(db_url=None):
    app = Flask(__name__)
    CORS(app)

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    logger.info("Flask app starting....")

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or "sqlite:///data.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = True

    app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')

    app.config["API_TITLE"] = "Stores REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config[
        "OPENAPI_SWAGGER_UI_URL"
    ] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"


    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    api = Api(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {"description": "The token has been revoked.", "error": "token_revoked"}
            ), 401
        )

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        user = UserModel.query.get(identity)
        if user:
            return {"role": user.role}
        return {"role": "user"}

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return (
            jsonify({"message": "The token has expired.", "error": "token_expired"}), 401
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify({"message": "Signature verification failed.", "error": "invalid_token"}), 401
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify({"description": "Request does not contain an access token.", "error": "authorization_required"}), 401
        )

    with app.app_context():
        db.create_all()

        superadmin_email = os.getenv("SUPERADMIN_EMAIL")
        superadmin_password = os.getenv("SUPERADMIN_PASSWORD")

        superadmin_first_name = os.getenv('SUPERADMIN_FIRST_NAME', 'Super')
        superadmin_last_name = os.getenv('SUPERADMIN_LAST_NAME', 'Admin')

        if superadmin_email and superadmin_password and not UserModel.query.filter_by(
                email=superadmin_email).first():
            superadmin = UserModel(
                email=superadmin_email,
                password=pbkdf2_sha256.hash(superadmin_password),
                first_name=superadmin_first_name,
                last_name=superadmin_last_name,
                role="superadmin",
                country="UK",
                is_email_verified=True
            )

            db.session.add(superadmin)
            db.session.commit()
            print("Super admin user created.")

    api.register_blueprint(UsersBlueprint, url_prefix="/auth")
    api.register_blueprint(StoreBlueprint, url_prefix="/store")
    api.register_blueprint(SupportBlueprint, url_prefix="/enquiries")

    return app
