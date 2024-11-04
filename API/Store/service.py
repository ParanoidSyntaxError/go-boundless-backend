import logging
import qrcode
import io
import requests 
import os
from API.Store.store_auth import get_store_access_token


from config import config

from API.extensions import db
from API.Auth.models import UserModel

mailgunAPIKey = config.Config.MAILGUN_API
EMAIL_FROM = config.Config.EMAIL_FROM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def activate_existing_customer(user, inventoryItemId, userIp, userCountry, expectedPrice, customerUid):
    url = 'https://api.giga.store/gigastore/activations/top-up-with-profile'
    headers = {
        'Authorization': f'Bearer {get_store_access_token()}',
        'Content-Type': 'application/json',
    }
    payload = {
        'inventoryItemId': inventoryItemId,
        'metatag': 'Paid via Stripe',
        'customerUid': customerUid or user.dent_uid,
        'userIp': userIp,
        'userCountry': userCountry,
        'expectedPrice': expectedPrice,
    }
    response = requests.post(url, headers=headers, json=payload)
    return response

def activate_new_customer(user, inventoryItemId, userIp, userCountry, expectedPrice):
    url = 'https://api.giga.store/gigastore/activations/register'
    headers = {
        'Authorization': f'Bearer {get_store_access_token()}',
        'Content-Type': 'application/json',
    }
    payload = {
        'inventoryItemId': inventoryItemId,
        'metatag': 'Paid via Stripe',
        'customerEmail': user.email,
        'userIp': userIp,
        'userCountry': userCountry,
        'expectedPrice': expectedPrice,
    }
    response = requests.post(url, headers=headers, json=payload)
    return response


def handle_activation(customerEmail, inventoryItemId, userIp, userCountry, expectedPrice, customerUid):
    logger.info(f"Starting activation for email: {customerEmail}, inventoryItemId: {inventoryItemId}")

    user = UserModel.query.filter_by(email=customerEmail).first()
    if user:
        logger.info(f"User found: {user.email}, is_new_customer: {user.is_new_customer}")
        if user.is_new_customer:
            response = activate_new_customer(
                user,
                inventoryItemId,
                userIp,
                userCountry,
                expectedPrice
            )
            logger.info(f"Response from activate_new_customer: {response.status_code}, {response.text}")
            if response.status_code == 200:
                user.is_new_customer = False
                user.dent_uid = response.json()['customer']['uid']
                db.session.commit()
            else:
                logger.error(f"Activation failed: {response.text}")
                raise Exception(f'Activation failed: {response.text}')
        else:
            response = activate_existing_customer(
                user,
                inventoryItemId,
                userIp,
                userCountry,
                expectedPrice,
                customerUid
            )
            logger.info(f"Response from activate_existing_customer: {response.status_code}, {response.text}")

        if response.status_code == 200:
            activation_data = response.json()
            esim_profile = activation_data.get('esimProfile')
            if esim_profile:
                activation_code = esim_profile.get('activationCode')
                logger.info(f"Activation code received: {activation_code}")
                qr_img = generate_qr_code(activation_code)
                send_activation_email(user.email, qr_img, activation_code)
            else:
                logger.error("No eSIM profile returned in activation response.")
        else:
            logger.error(f"Activation failed: {response.text}")
            raise Exception(f'Activation failed: {response.text}')
    else:
        logger.error(f"User with email {customerEmail} not found.")
        return


def generate_qr_code(data):
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf


def send_activation_email(email, qr_img, activation_code):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/activation_email.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{activation_code}}', activation_code)
    html_content = html_content.replace('{{activation_link}}', activation_code)  

    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "Your eSIM Activation Code",
        "html": html_content
    }

    files = [("inline", ("qr_code.png", qr_img, 'image/png'))]

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data,
        files=files
    )

    return response
