# utils.py
from django.core.mail import send_mail
from django.conf import settings
import logging

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

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




def validate_password(password):
    if len(password) < 6:
        raise ValidationError(_("Password must be at least 8 characters long."))

    if " " in password:
        raise ValidationError(_("Password should not contain spaces."))

    return password
