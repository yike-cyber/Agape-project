# utils.py
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def send_email(subject, message, recipient_list):
    try:
        response = send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            recipient_list,
        )
        logger.info(f"Email sent successfully to: {', '.join(recipient_list)}")
        return response
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return None
