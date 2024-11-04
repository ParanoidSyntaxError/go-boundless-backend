import uuid
from flask import request, jsonify, url_for, redirect, current_app
from flask.views import MethodView
import pyotp
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError
from config import config
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt
import bcrypt 
import random
import string
from datetime import datetime, timedelta

from API.extensions import db, limiter
from blocklist import BLOCKLIST 
from API.Auth.models import UserModel 

from API.Auth.service import send_password_reset_email, send_verification_code_email

import logging

logger = logging.getLogger(__name__)

blp = Blueprint("users", __name__, description="Operations on users")

## TO DO ADD MARKETING PREFERENCE AND DOB TO REGISTRATION
@blp.route("/register", methods=["POST"])
class UserRegister(MethodView):
    def post(self):
        """
        Register a new user.

        ---
        tags:
          - Authentication
        parameters:
          - in: body
            name: user
            description: User registration details.
            required: true
            schema:
              type: object
              required:
                - email
                - first_name
                - last_name
                - country
                - password
                - org_name
              properties:
                email:
                  type: string
                  format: email
                  example: user@example.com
                first_name:
                  type: string
                  example: john
                last_name:
                  type: string
                  example: Doe
                password:
                  type: string
                  example: password123
                country:
                  type: string
                  example: GB
        responses:
          201:
            description: User registered successfully.
          400:
            description: Invalid data or user already exists.
        """

        user_data = request.get_json()

        required_fields = ["email", "first_name", "last_name", "country", "password"]
        missing_fields = [field for field in required_fields if field not in user_data]

        if missing_fields:
            abort(400, message=f"Missing fields: {', '.join(missing_fields)}")

        if UserModel.query.filter(UserModel.email == user_data["email"]).first():
            abort(409, message="Your email is already registered")

        verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        verification_code_expiry = datetime.utcnow() + timedelta(minutes=15)

        user = UserModel(
            email=user_data["email"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            password=bcrypt.hashpw(user_data["password"].encode('utf-8'), bcrypt.gensalt()),
            role="user",
            verification_code=verification_code,
            verification_code_expiry=verification_code_expiry,
            country=user_data["country"]
        )

        db.session.add(user)
        db.session.commit()

        send_verification_code_email(user.email, verification_code)

        return {
            "message": "Registration successful. Please enter the verification code sent to your email."
        }, 201
    

@blp.route("/login")
class UserLogin(MethodView):
    @limiter.limit("5 per minute")
    def post(self, user_data):
        """
        Login as a user and get access tokens.

        ---
        tags:
          - Authentication
        parameters:
          - in: body
            name: user
            description: User login details.
            required: true
            schema:
              type: object
              required:
                - email
                - password
              properties:
                email:
                  type: string
                password:
                  type: string
        responses:
          200:
            description: Return access and refresh tokens.
          401:
            description: Invalid credentials.
        """
        user = UserModel.query.filter(
            UserModel.email == user_data["email"]
        ).first()

        if user and bcrypt.checkpw(user_data["password"].encode('utf-8'),user.password.encode('utf-8')):
            if not user.is_email_verified:
                abort(403, message="You have not verified your account. Please check your email.")
            else:
                access_token = create_access_token(identity=user.id, fresh=True)
                refresh_token = create_refresh_token(identity=user.id)
                return {"access_token": access_token, "refresh_token": refresh_token, "user_id": user.id}
        else:
            abort(401, message="Login details are incorrect")


## TO DO - ADD swagger
@blp.route("/user", methods=["POST"])
class UserDetails(MethodView):
    @jwt_required()
    def post(self):
        
        user_id = get_jwt_identity()
        user = UserModel.query.filter_by(id=user_id).first()

        if not user:
            abort(404, message="User not found.")

        return {
            "id": user.id,
            "dent_uid": user.dent_uid,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "birthdate": user.birthdate.isoformat() if user.birthdate else None,
            "currency": user.currency,
            "language": user.language,
            "marketing_emails": user.marketing_emails,
        }, 200
    
## TO DO - ADD swagger
## TO DO - Remove ability to add email
@blp.route("/edit-user", methods=["POST"])
class UserDetails(MethodView):
    @jwt_required()
    def post(self):
        data = request.get_json()
        user_id = get_jwt_identity()
        user = UserModel.query.filter_by(id=user_id).first()

        if not user:
            abort(404, message="User not found.")

        first_name = data.get("firstName")
        last_name = data.get("lastName")
        email = data.get("email")  
        birthdate = data.get("birthdate")  
        currency = data.get("currency", "USD")
        language = data.get("language", "English")
        marketing_emails = data.get("marketingEmails", False)

        if not first_name or not last_name:
            abort(400, message="First name and last name are required.")

        user.first_name = first_name
        user.last_name = last_name
        if email:
            user.email = email 
        if birthdate:
            try:
                user.birthdate = datetime.strptime(birthdate, "%Y-%m-%d").date()
            except ValueError:
                abort(400, message="Invalid birthdate format. Use YYYY-MM-DD.")
        user.currency = currency
        user.language = language
        user.marketing_emails = marketing_emails

        try:
            db.session.commit()
            logger.info(f"User {user.email} updated their profile.")
            return jsonify({"message": "Profile updated successfully."}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating user profile: {e}")
            abort(500, message="An error occurred while updating your profile.")

            

@blp.route("/verify-code", methods=["POST"])
class VerifyCode(MethodView):
    @limiter.limit("5 per minute")
    def post(self):
        """
        Verify the alphanumeric code sent to the user's email.

        ---
        tags:
          - Authentication
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - email
                  - code
                properties:
                  email:
                    type: string
                    format: email
                    example: "user@example.com"
                  code:
                    type: string
                    example: "AB12CD"
        responses:
          200:
            description: Email verified and tokens returned.
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    message:
                      type: string
                    access_token:
                      type: string
                    refresh_token:
                      type: string
                    user_id:
                      type: integer
                    expires_in:
                      type: integer
          400:
            description: Invalid code or code expired.
          404:
            description: User not found.
        """
        data = request.get_json()
        email = data.get('email')
        code = data.get('code')

        user = UserModel.query.filter_by(email=email).first()

        if not user:
            logger.warning(f"Verification attempt for non-existent user email: {email}")
            abort(404, message="User not found.")

        current_time = datetime.utcnow()

        if not user.verification_code_expiry or current_time > user.verification_code_expiry:
            logger.warning(f"Verification code expired for user email: {email}")
            abort(400, message="Verification code has expired.")

        if user.verification_code != code:
            logger.warning(f"Invalid verification code attempt for user email: {email}")
            abort(400, message="Invalid verification code.")

        user.is_email_verified = True
        user.verification_code = None
        user.verification_code_expiry = None
        db.session.commit()

        logger.info(f"User email verified successfully: {email}")

        
        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_refresh_token(identity=user.id)
        expires_in = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
        if hasattr(expires_in, 'total_seconds'):
            expires_in = int(expires_in.total_seconds())
        else:
            expires_in = int(expires_in)

        return {
            "message": "Email verified successfully.",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.id,
            "expires_in": expires_in
        }, 200
    
@blp.route("/resend-verification-code", methods=["POST"])
class ResendVerificationCode(MethodView):
    @limiter.limit("3 per hour")
    def post(self):
        data = request.get_json()
        email = data.get('email')

        user = UserModel.query.filter_by(email=email).first()

        if not user:
            logger.warning(f"Resend verification code attempt for non-existent user email: {email}")
            abort(404, message="User not found.")

        verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        verification_code_expiry = datetime.utcnow() + timedelta(minutes=15)

        user.verification_code = verification_code
        user.verification_code_expiry = verification_code_expiry
        db.session.commit()

        send_verification_code_email(user.email, verification_code)

        logger.info(f"Verification code resent to user email: {email}")

        return {"message": "A new verification code has been sent to your email."}, 200


## Reset Password 
@blp.route("/reset-password/<token>")
class ResetPassword(MethodView):
    def post(self, token):
        """
           Reset Password with token
           ---
           tags:
                - Authentication
           parameters:
             - in: header
               name: Authorization
               description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
             - in: body
               name: body
               description: Use reset token to reset password
               required: true
               schema:
                 type: object
                 required:
                   - new_password
                 properties:
                   new_password:
                     type: string
           responses:
             200:
               description: Password reset successful.
             400:
               description: Password reset failed.
           """
        json_data = request.get_json()
        new_password = json_data.get('password')

        user = UserModel.query.filter_by(reset_password_token=token).first()
        if not user:
            abort(404, description="Error resetting password. Contact Support")

        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.reset_password_token = None
        db.session.commit()

        return jsonify({"message": "Your password has been updated successfully."}), 200


# API/Auth/views.py

import uuid
import secrets
from flask import request, jsonify, url_for, current_app
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta

from API.extensions import db, limiter
from API.Auth.models import UserModel 
from API.Auth.service import send_password_reset_email

import logging

logger = logging.getLogger(__name__)

blp = Blueprint("users", __name__, description="Operations on users")

@blp.route("/forgot-password")
class ForgotPassword(MethodView):
    decorators = [limiter.limit("5 per minute")] 

    def post(self):
        """
            Request a password reset.
            ---
            tags:
              - Authentication
            summary: Request a password reset
            parameters:
              - in: body
                name: body
                description: Email to send reset token to
                required: true
                schema:
                  type: object
                  required:
                    - email
                  properties:
                    email:
                      type: string
                      format: email  
            responses:
              200:
                description: Forgotten password request sent successfully.
              400:
                description: Bad request - Missing or invalid email format
              429:
                description: Too Many Requests - Please wait before retrying
            """
        json_data = request.get_json()
        email = json_data.get('email')

        if not email:
            return jsonify({"message": "Email is required."}), 400

        user = UserModel.query.filter_by(email=email).first()
        if not user:
            
            return jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200

        current_time = datetime.now(datetime.timezone.utc)

        if user.last_password_email_time:
            time_since_last_email = current_time - user.last_password_email_time
            if time_since_last_email < timedelta(minutes=1):
                wait_time = 60 - int(time_since_last_email.total_seconds())
                return jsonify({"message": f"Please wait {wait_time} seconds before requesting another password reset."}), 429

        
        user.reset_password_token = secrets.token_urlsafe(32)
        user.reset_password_token_expiry = current_time + timedelta(hours=1)  
        user.last_password_email_time = current_time
        db.session.commit()

        
        reset_link = url_for('users.ResetPassword', token=user.reset_password_token, _external=True, _scheme='https')

        
        try:
            send_password_reset_email(user.email, reset_link)
            logger.info(f"Password reset email sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send password reset email to {user.email}: {e}")
            return jsonify({"message": "Failed to send password reset email. Please try again later."}), 500

        return jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200 
