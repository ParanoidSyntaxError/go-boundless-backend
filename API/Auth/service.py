import requests
import os
from config import config

mailgunAPIKey = config.Config.MAILGUN_API
EMAIL_FROM = config.Config.EMAIL_FROM

def send_verification_code_email(email, verification_code):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/verification_code.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{verification_code}}', verification_code)

    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "Your Verification Code",
        "html": html_content
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response


## Send verification email
def send_password_reset_email(email, reset_link):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/forgot_password.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    html_content = html_content.replace('{{password_reset_link}}', reset_link)

    email_data = {
        "from": EMAIL_FROM,
        "to": email,
        "subject": "Password Reset Request",
        "html": html_content,
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response