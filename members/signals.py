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