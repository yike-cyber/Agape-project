import random

from django.core.email import EmailMessage
from .models import User,OneTimePassword
from django.conf import settings

def generate_otp():
    otp = ''
    for i in range(6):
        otp +=str(random.randInt(1,9))
    return otp 

def send_code_to_user(email):
    subject = 'One time passcode for email verification'
    otp_code = generate_otp()
    print('otp code ',otp_code)
    
    user = User.objects.get(email = email)
    current_site = 'myauth.com'
    email_body = f'hi {user.first_name} thanks for signing up on {current_site} please verify your email with the \n one time passcode {otp_code}'
    from_email = settings.DEFAULT_FROM_EMAIL
    
    OneTimePassword.objects.create(user = user,code = otp_code)
    send_email = EmailMessage(subject = subject,body = email_body,from_email = from_email)
    send_email.send(fail_silently = True,)
    
    