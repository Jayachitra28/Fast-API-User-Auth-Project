# email_utils.py

import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")


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


def send_reset_email(to_email: str, reset_link: str):
    subject = "Reset your password"
    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_SENDER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(f"Click the link below to reset your password:\n\n{reset_link}")

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print("Error sending email:", e)

