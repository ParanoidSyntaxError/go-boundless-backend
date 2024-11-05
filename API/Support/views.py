from flask import jsonify, request
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError

from API.extensions import db
from API.Support.models import SupportModel
from API.Support.service import send_enquiry
from datetime import datetime, timezone

blp = Blueprint("support", __name__, description="Operations on support")

@blp.route("/enquiry")
class Enquiry(MethodView):
    def post(self):
        """
        Create a new enquiry and send an email
        ---
        tags:
            - Enquiry
        parameters:
          - in: header
            name: Authorization
            description: Bearer JWT token
            required: true
            schema:
              type: string
          - in: body
            name: body
            description: Sales enquiry data
            required: true
            schema:
              type: object
              required:
                - first_name
                - email
                - message
              properties:
                first_name:
                  type: string
                last_name:
                  type: string  
                email:
                  type: string
                subject:
                  type: string
                message:
                  type: string
                
        responses:
          200:
            description: Enquiry successfully added and email sent.
          400:
            description: Bad request.
          500:
            description: Internal server error.
        """
        enquiry_data = request.get_json()

        new_enquiry = SupportModel(
            first_name=enquiry_data.get("first_name"),
            last_name=enquiry_data.get("last_name"),
            subject=enquiry_data.get("subject"),
            enquiry_date=datetime.now(timezone.utc),
            message=enquiry_data.get("message"),
            email=enquiry_data.get("email"),

        )

        try:
            db.session.add(new_enquiry)
            db.session.commit()

            send_enquiry(new_enquiry)

            return jsonify({"message": "Enquiry successfully added and email sent."}), 200

        except SQLAlchemyError as e:
            db.session.rollback()
            abort(500, message=str(e))

        except Exception as e:
            abort(500, message=f"An error occurred: {str(e)}")