from flask import Blueprint, jsonify, request
import requests
import stripe
import base64
from config.config import Config
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from requests.auth import HTTPBasicAuth 
import json 
from API.Store.service import handle_activation 
from API.Store.store_auth import get_store_access_token
import logging

## TO DO - Switch to post requests
## TO DO - Swap out dent link for variable


from API.Auth.models import UserModel

from API.extensions import db 

stripe.api_key = Config.STRIPE_PRIVATE_KEY
endpoint_secret = Config.STRIPE_ENDPOINT_SECRET

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info("Logger is active in store views...")

blp = Blueprint("store", __name__, description="Operations on store")

def generate_basic_auth_header(client_id, client_secret):
    credentials = f"{client_id}:{client_secret}"
    credentials_bytes = credentials.encode('utf-8')
    base64_bytes = base64.b64encode(credentials_bytes)
    base64_credentials = base64_bytes.decode('utf-8')
    return f"Basic {base64_credentials}"

@blp.route('/authenticate', methods=['POST'])
def authenticate():
    client_id = Config.CLIENT_ID
    client_secret = Config.CLIENT_SECRET

    try:
        response = requests.post(
            'https://api.giga.store/reseller/authenticate',
            auth=HTTPBasicAuth(client_id, client_secret),
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": "HTTP Error", "message": str(errh)}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request Exception", "message": str(e)}), 500


@blp.route('/inventory', methods=['GET'])
def get_inventory():
    access_token = request.headers.get('Authorization')

    if not access_token:
        return jsonify({"error": "Unauthorized", "message": "Missing access token"}), 401

    headers = {
        'Authorization': access_token,  
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get('https://api.giga.store/gigastore/products/inventory', headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": "HTTP Error", "message": str(errh)}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request Exception", "message": str(e)}), 500


@blp.route('/customers', methods=['GET'])
def get_customers():
    access_token = request.headers.get('Authorization')

    if not access_token:
        return jsonify({"error": "Unauthorized", "message": "Missing access token"}), 401

    page_size = request.args.get('page_size', default=50, type=int)
    page_index = request.args.get('page_index', default=0, type=int)

    if page_size <= 0 or page_index < 0:
        return jsonify({"error": "Invalid Parameters", "message": "page_size must be positive and page_index cannot be negative."}), 400

    external_api_url = f'https://api.giga.store/gigastore/activations/customers?page_size={page_size}&page_index={page_index}'

    headers = {
        'Authorization': access_token,  
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(external_api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": "HTTP Error", "message": str(errh)}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request Exception", "message": str(e)}), 500


@blp.route('/customer/<string:customer_uid>', methods=['GET'])
def get_customer(customer_uid):
    access_token = request.headers.get('Authorization')

    if not access_token:
        return jsonify({"error": "Unauthorized", "message": "Missing access token"}), 401

    external_api_url = f'https://api.giga.store/gigastore/activations/customers/{customer_uid}'

    headers = {
        'Authorization': access_token,  
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(external_api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": "HTTP Error", "message": str(errh)}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request Exception", "message": str(e)}), 500


## TO DO (NON URGENT) Get all Activated items for admin backend


## Get Customers sims
@blp.route('/customer-activations', methods=['POST'])
@jwt_required()
def customer_activations():
    user_id = get_jwt_identity()
    user = UserModel.query.filter_by(id=user_id).first()

    if not user:
        logger.error("User not found.")
        return jsonify({"error": "User not found"}), 404

    if not user.dent_uid:
        logger.error("User does not have a dent_uid.")
        return jsonify({"error": "No product found. Please add a product."}), 400

    dent_uid = user.dent_uid

    # Get the store access token
    external_api_access_token = get_store_access_token()
    if not external_api_access_token:
        logger.error("Failed to obtain store access token.")
        return jsonify({"error": "Authentication Error", "message": "Failed to authenticate with external API"}), 500

    external_api_url = f'https://api.giga.store/gigastore/activations/customers/{dent_uid}'

    headers = {
        'Authorization': f'Bearer {external_api_access_token}',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(external_api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify({"activatedItems": data}), 200
    except requests.exceptions.HTTPError as errh:
        logger.error(f"HTTP Error: {errh}")
        return jsonify({"error": "HTTP Error", "message": str(errh)}), errh.response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Request Exception: {e}")
        return jsonify({"error": "Request Exception", "message": str(e)}), 500

## Get an activated item by its UID

@blp.route('/activated-items/<string:item_uid>', methods=['POST'])
@jwt_required()
def get_activated_item(item_uid):
    user_id = get_jwt_identity()
    user = UserModel.query.filter_by(id=user_id).first()

    if not user or not user.dent_uid:
        logger.error("User not found or dent_uid not set.")
        return jsonify({"error": "User not found or dent_uid not set"}), 404

    dent_uid = user.dent_uid
    access_token = request.headers.get('Authorization')

    if not access_token:
        return jsonify({"error": "Unauthorized", "message": "Missing access token"}), 401

    external_api_url = f'https://api.giga.store/gigastore/activations/activated-items/{item_uid}'

    headers = {
        'Authorization': access_token,
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(external_api_url, headers=headers)
        response.raise_for_status()
        data = response.json()

        customer = data.get('customer', {})
        if customer.get('uid') != dent_uid:
            logger.error("Activated item does not belong to the user.")
            return jsonify({"error": "Activated item does not belong to the user"}), 403

        return jsonify(data), 200
    except requests.exceptions.HTTPError as errh:
        logger.error(f"HTTP Error: {errh}")
        return jsonify({"error": "HTTP Error", "message": str(errh)}), errh.response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Request Exception: {e}")
        return jsonify({"error": "Request Exception", "message": str(e)}), 500


## get connectivity information

## Supported Devices
@blp.route('/devices', methods=['GET'])
def get_devices():
    access_token = request.headers.get('Authorization')

    if not access_token:
        return jsonify({"error": "Unauthorized", "message": "Missing access token"}), 401

    headers = {
        'Authorization': access_token,  
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get('https://api.giga.store/gigastore/esim/device/esim-capable', headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": "HTTP Error", "message": str(errh)}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request Exception", "message": str(e)}), 500

## Countries 
@blp.route('/countries', methods=['GET'])
def get_countries():
    access_token = request.headers.get('Authorization')

    if not access_token:
        return jsonify({"error": "Unauthorized", "message": "Missing access token"}), 401

    headers = {
        'Authorization': access_token,  
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get('https://api.giga.store/gigastore/esim/countries/WWW', headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify(data)
    except requests.exceptions.HTTPError as errh:
        return jsonify({"error": "HTTP Error", "message": str(errh)}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request Exception", "message": str(e)}), 500

## PAYMENTS

@blp.route('/create-payment-intent', methods=['POST'])
def create_payment_intent():
    data = request.get_json()
    try:
        amount = data['amount']
        currency = data.get('currency', 'usd')
        payment_method_id = data['payment_method_id']
        inventoryItemId = data.get('inventoryItemId')
        customerEmail = data.get('customerEmail')
        userIp = data.get('userIp', '')
        userCountry = data.get('userCountry', '')
        expectedPrice = data.get('expectedPrice', {})
        customerUid = data.get('customerUid', '') 

        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency,
            payment_method=payment_method_id,
            confirmation_method='manual',
            confirm=True,
            return_url='http://localhost:5173//payment-success',
            metadata={
                'inventoryItemId': inventoryItemId,
                'customerEmail': customerEmail,
                'userIp': userIp,
                'userCountry': userCountry,
                'expectedPrice': json.dumps(expectedPrice), 
                'customerUid': customerUid,
            },
        )

        return jsonify({'client_secret': intent.client_secret}), 200
    except Exception as e:
        return jsonify(error=str(e)), 403
    
@blp.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        return jsonify(success=False), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify(success=False), 400

    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        metadata = payment_intent.get('metadata', {})

        inventoryItemId = metadata.get('inventoryItemId')
        customerEmail = metadata.get('customerEmail')
        userIp = metadata.get('userIp', '')
        userCountry = metadata.get('userCountry', '')
        expectedPrice_str = metadata.get('expectedPrice', '{}')
        expectedPrice = json.loads(expectedPrice_str)
        customerUid = metadata.get('customerUid', '')

        try:
            handle_activation(customerEmail, inventoryItemId, userIp, userCountry, expectedPrice, customerUid)
        except Exception as e:
            logger.exception("Activation error")
            return jsonify(success=False), 500
            
    elif event['type'] == 'payment_intent.payment_failed':
        payment_intent = event['data']['object']
        print('Payment failed:', payment_intent['last_payment_error']['message'])
    else:
        logger.info('Unhandled event type {}'.format(event['type']))
        print('Unhandled event type {}'.format(event['type']))

    return jsonify(success=True), 200