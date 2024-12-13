from flask import Blueprint, jsonify, request
import requests
import stripe
import base64
from config.config import Config
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from requests.auth import HTTPBasicAuth 
import json 
from API.Store.service import handle_activation,  create_payment_invoice
from API.Store.store_auth import get_store_access_token
from API.Store.models import SimModel
import logging

## TO DO - Switch to post requests

from API.Auth.models import UserModel

from API.extensions import db 

stripe.api_key = Config.STRIPE_PRIVATE_KEY
endpoint_secret = Config.STRIPE_ENDPOINT_SECRET
now_payment_api_key = Config.NOW_PAYMENT_API_KEY
now_payment_link = Config.NOW_PAYMENT_API_LINK
dent_link = Config.DENT_LINK

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
            f'{dent_link}/reseller/authenticate',
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
        response = requests.get(f'{dent_link}/gigastore/products/inventory', headers=headers)
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

    external_api_url = f'{dent_link}/gigastore/activations/customers?page_size={page_size}&page_index={page_index}'

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

    external_api_url = f'{dent_link}/gigastore/activations/customers/{customer_uid}'

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

    external_api_url = f'{dent_link}/gigastore/activations/customers/{dent_uid}'

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

    external_api_url = f'{dent_link}/gigastore/activations/activated-items/{item_uid}'

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
        response = requests.get(f'{dent_link}/gigastore/esim/device/esim-capable', headers=headers)
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
        response = requests.get(f'{dent_link}/gigastore/esim/countries/WWW', headers=headers)
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
            return_url='https://goboundlessnow.com/payment-success',
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

@blp.route('/pending-activations', methods=['POST'])
@jwt_required()
def get_pending_activations():
    user_id = get_jwt_identity()
    user = UserModel.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    activation = SimModel.query.filter_by(user_id=user_id).order_by(SimModel.created_at.desc()).first()

    if not activation:
        return jsonify({"error": "No pending activations found"}), 404

    activation_data = {
        'id': activation.id,
        'activation_code': activation.activation_code,
        'installation_url': activation.installation_url,
        'status': activation.status,
        'created_at': activation.created_at.isoformat(),
    }

    return jsonify(activation_data), 200

@blp.route('/gigastore-webhook/esim-status', methods=['POST'])
def esim_status_webhook():
    data = request.get_json()

    iccid = data.get('iccid')
    imsi = data.get('imsi')
    profile_state = data.get('profileState')
    eid = data.get('eid')

    if not iccid or not imsi or not profile_state:
        logger.error("Missing required fields in webhook payload.")
        return jsonify({"error": "Missing required fields"}), 400

    activation = SimModel.query.filter_by(iccid=iccid).first()

    if not activation:
        logger.error(f"Activation with ICCID {iccid} not found.")
        return jsonify({"error": "Activation not found"}), 404
    
    activation.status = profile_state.upper() 
    db.session.commit()
    logger.info(f"Activation status updated to {activation.status} for ICCID {iccid}.")

    return jsonify({"message": "Activation status updated"}), 200

@blp.route('/payment_provider_status', methods=['POST'])
def check_nowpayments_status():
    response = requests.get(f'{now_payment_link}/status')
    return response.json()

@blp.route('/available_currencies', methods=['POST'])
def get_available_currencies():
    headers = {
        'x-api-key': now_payment_api_key,
    }
    print("Using NowPayments API Key:", now_payment_api_key)  # Debug statement
    response = requests.get(f'{now_payment_link}/currencies?fixed_rate=true', headers=headers)
    return response.json()

# @blp.route('/minimum-payment-amount', methods=['POST'])
# def minimum_payment_amount_route():
#     data = request.get_json()
#     currency_from = data['currency_from']
#     currency_to = data.get('currency_to', 'usd')
#     min_amount_data = get_minimum_payment_amount(currency_from, currency_to)
#     if 'min_amount' in min_amount_data:
#         return jsonify(min_amount_data), 200
#     else:
#         return jsonify(error='Failed to fetch minimum payment amount'), 400

# @blp.route('/estimated-price', methods=['POST'])
# def estimated_price_route():
#     data = request.get_json()
#     amount = data['amount']
#     currency_from = data.get('currency_from', 'usd')
#     currency_to = data['currency_to']
#     estimated_price = get_estimated_price(amount, currency_from, currency_to)
#     if 'estimated_amount' in estimated_price:
#         return jsonify(estimated_price), 200
#     else:
#         return jsonify(error='Failed to fetch estimated price'), 400

# Comment out if using IPN logic instead
# @blp.route('/get-payment-status/<payment_id>', methods=['GET'])
# def get_payment_status_route(payment_id):
#     headers = {
#         'x-api-key': now_payment_api_key,
#     }
#     response = requests.get(f'{now_payment_link}/payment/{payment_id}', headers=headers)
#     status_data = response.json()

#     if 'payment_status' in status_data:
#         payment_status = status_data['payment_status']

#         if payment_status == 'finished':
#             # Check if activation has already been processed for this payment
#             existing_activation = SimModel.query.filter_by(payment_id=payment_id).first()
#             if not existing_activation:
#                 # Retrieve necessary data from payment_response or your database
#                 customer_email = status_data.get('customer_email') or status_data.get('order_description')  # Adjust as needed
#                 inventory_item_id = status_data.get('order_id')
#                 user_ip = ''  # If you have this stored somewhere
#                 user_country = ''  # If you have this stored somewhere
#                 expected_price = {
#                     'priceValue': status_data.get('price_amount'),
#                     'currencyCode': status_data.get('price_currency')
#                 }
#                 customer_uid = ''  # If you have this stored somewhere

#                 try:
#                     # Call the activation function
#                     handle_activation(customer_email, inventory_item_id, user_ip, user_country, expected_price, customer_uid)

#                     # Store the payment_id to prevent duplicate activations
#                     new_activation = SimModel(
#                         payment_id=payment_id,
#                         user_email=customer_email,
#                         status='ACTIVATED',
#                         # Include other necessary fields
#                     )
#                     db.session.add(new_activation)
#                     db.session.commit()

#                 except Exception as e:
#                     logger.exception("Activation error")
#                     return jsonify({"error": "Activation failed"}), 500

#             return jsonify(status_data), 200
#         else:
#             # Return the current payment status
#             return jsonify(status_data), 200
#     else:
#         return jsonify({"error": "Failed to get payment status"}), 500


# @blp.route('/create-crypto-payment', methods=['POST'])
# def create_crypto_payment_route():
#     data = request.get_json()
#     try:
#         amount = data['amount']  
#         pay_currency = data['pay_currency'] 
#         customer_email = data['customerEmail']
#         order_id = data.get('order_id', '')
#         order_description = data.get('order_description', '')
#         inventoryItemId = data.get('inventoryItemId')
#         userIp = data.get('userIp', '')
#         userCountry = data.get('userCountry', '')
#         expectedPrice = data.get('expectedPrice', {})
#         customerUid = data.get('customerUid', '')

#         # Estimate Price
#         estimated_price = get_estimated_price(amount, 'usd', pay_currency)
#         if 'estimated_amount' not in estimated_price:
#             return jsonify(error='Error estimating price'), 400

#         # Check Minimum Amount
#         min_amount_data = get_minimum_payment_amount(pay_currency, 'usd')
#         if 'min_amount' in min_amount_data and estimated_price['estimated_amount'] < min_amount_data['min_amount']:
#             return jsonify(error='Amount is less than minimum allowed'), 400

#         # Create Payment
#         headers = {
#             'x-api-key': now_payment_api_key,
#             'Content-Type': 'application/json',
#         }
#         data = {
#             'price_amount': amount,
#             'price_currency': 'usd',
#             'pay_currency': pay_currency,
#             'order_id': order_id,
#             'order_description': order_description,
#             'customer_email': customer_email,
#         }
#         response = requests.post(f'{now_payment_link}/payment', headers=headers, json=data)
#         payment_response = response.json()

#         if 'payment_id' not in payment_response:
#             return jsonify(error='Error creating payment'), 400

#         return jsonify(payment_response), 200
#     except Exception as e:
#         return jsonify(error=str(e)), 500


## IPN CALLBACK LINK - Update and activate sim on payment success

@blp.route('/create-invoice', methods=['POST'])
def create_invoice():
    data = request.json
    amount = data.get("amount")
    currency = data.get("currency", "usd")  
    ipn_callback_url = data.get("ipn_callback_url")
    success_url = data.get("success_url")
    cancel_url = data.get("cancel_url")

    invoice_data = create_payment_invoice(amount, currency, ipn_callback_url, success_url, cancel_url)
    if invoice_data:
        return jsonify(invoice_data), 200
    else:
        return jsonify({"error": "Failed to create invoice"}), 500
    
@blp.route('/ipn-callback', methods=['POST'])
def ipn_callback():
    data = request.json
    invoice_id = data.get("id")
    payment_status = data.get("status")  

    if payment_status == "completed":
        customer_email = data.get("customer_email")
        inventory_item_id = data.get("order_id")  
        try:
            handle_activation(customer_email, inventory_item_id, "userIp", "userCountry", "expectedPrice", "customerUid")
            return jsonify({"status": "success"}), 200
        except Exception as e:
            logger.exception("Activation failed")
            return jsonify({"status": "failed", "error": str(e)}), 500
    else:
        return jsonify({"status": "payment_failed"}), 400