import requests
import os
from config.config import Config
from datetime import datetime

mailgunAPIKey = Config.MAILGUN_API
EMAIL_FROM = Config.EMAIL_FROM
SUPPORT_TEAM_EMAILS = Config.SUPPORT_TEAM_EMAILS.split(",")


def send_enquiry(enquiry):
    enquiry_date_str = enquiry.enquiry_date.strftime("%Y-%m-%d %H:%M:%S") if enquiry.enquiry_date else "N/A"

    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, 'Resources/enquiry.html')

    with open(template_path, 'r', encoding='utf-8') as file:
        html_content = file.read()


    html_content = html_content.replace('{{first_name}}', enquiry.first_name)
    html_content = html_content.replace('{{last_name}}', enquiry.last_name)
    html_content = html_content.replace('{{subject}}', enquiry.subject)
    html_content = html_content.replace('{{enquiry_date}}', enquiry_date_str) 
    html_content = html_content.replace('{{email}}', enquiry.email)
    html_content = html_content.replace('{{message}}', enquiry.message or "No message provided")

    email_data = {
        "from": EMAIL_FROM,
        "to": SUPPORT_TEAM_EMAILS,  
        "subject": "New Enquiry from Go Boundless Website",
        "html": html_content,
    }

    response = requests.post(
        "https://api.mailgun.net/v3/mailerus.liquify.io/messages",
        auth=("api", mailgunAPIKey),
        data=email_data
    )

    return response
