# In members/utils/email_otp.py
import random
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.core.cache import cache
from members.models import EmailVerificationOTP 

def create_and_send_email_otp(user, email):
    # First, expire any existing OTPs for this user/email
    EmailVerificationOTP.objects.filter(
        user=user,
        email=email,
        is_used=False
    ).update(is_used=True)
    
    # Generate a 6-digit code# 
    code = str(random.randint(100000, 999999)).strip()
    
    # Create new OTP record
    otp = EmailVerificationOTP.objects.create(
        user=user,
        email=email,
        code=code,
        expires_at=timezone.now() + timezone.timedelta(minutes=15)
    )
    
    # Send email
    send_mail(
        'Your Verification Code',
        f'Your verification code is: {code}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
    
    return otp