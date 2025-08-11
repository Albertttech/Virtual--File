# In members/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import MemberAccount
from django.db.models.signals import post_save
from django.dispatch import receiver
from paystackapi.transaction import Transaction
from .models import UserPurchase
from .views import get_paystack_credentials


@receiver(post_save, sender=UserPurchase)
def verify_purchase(sender, instance, created, **kwargs):
    if created and not instance.is_verified:
        # Verify with Paystack if not already verified
        credentials = get_paystack_credentials()
        try:
            response = Transaction.verify(
                reference=instance.payment_reference,
                authorization_key=credentials['secret_key']
            )
            if response['status']:
                instance.is_verified = True
                instance.save()
        except Exception as e:
            print(f"Error verifying purchase: {str(e)}")



@receiver(post_save, sender=MemberAccount)
def update_auth_email(sender, instance, **kwargs):
    if instance.authentication_email:
        # Ensure email is normalized
        instance.authentication_email = instance.authentication_email.lower().strip()
        # Update verification status
        instance.is_email_authenticated = True
        # Avoid infinite loop
        MemberAccount.objects.filter(pk=instance.pk).update(
            authentication_email=instance.authentication_email,
            is_email_authenticated=True
        )