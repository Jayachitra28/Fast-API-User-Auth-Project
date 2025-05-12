# email_utils.py

import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def send_welcome_email(to_email):

    try:
        msg = EmailMessage()
        msg['Subject'] = '🎉 Welcome to Our FastAPI App!'
        msg['From'] = EMAIL_SENDER
        msg['To'] = to_email
        msg.set_content("Hi,\n\nThanks for registering with us!\n\n- Team")
       
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
            
    except Exception as e:
        print(f" Error occurred while sending email: {e}")
