#members/email_otp.py
from django.core.mail import EmailMultiAlternatives
from members.models import EmailVerificationOTP

def create_and_send_email_otp(user, email):
    # Create the OTP instance
    otp = EmailVerificationOTP.objects.create_otp(user=user, email=email)

    # Prepare the email content
    subject = "Your VCF Member verification code"
    body = f"Your verification code is {otp.otp_code}.\n\nThis code will expire at {otp.expires_at}."

    # Send the email
    email_message = EmailMultiAlternatives(subject, body, to=[email])
    email_message.send()

    # Return the created OTP instance
    return otp
