# In members/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.cache import cache
from .models import MemberAccount, UserPurchase
from customadmin.models import VCFFile
from paystackapi.transaction import Transaction
from .views import get_paystack_credentials


# In members/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.cache import cache
from .models import MemberAccount, UserPurchase
from customadmin.models import VCFFile


@receiver(post_save, sender=UserPurchase)
def verify_purchase_async(sender, instance, created, **kwargs):
    """Use Celery task for async payment verification"""
    if created and not instance.is_verified:
        try:
            from .tasks import verify_paystack_payment_async
            # Delay the task by 30 seconds to allow Paystack to process
            verify_paystack_payment_async.apply_async(
                args=[instance.id], 
                countdown=30
            )
        except ImportError:
            # Fallback to synchronous verification if Celery is not available
            from paystackapi.transaction import Transaction
            from .views import get_paystack_credentials
            
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


@receiver(post_save, sender=UserPurchase)
def invalidate_vcf_cache_on_purchase(sender, instance, **kwargs):
    """Invalidate VCF tabs cache when user purchase changes"""
    try:
        from .tasks import invalidate_user_cache
        invalidate_user_cache.delay(instance.user.id)
    except ImportError:
        # Fallback to direct cache deletion
        cache_keys = [
            f"vcf_tabs_{instance.user.id}",
            f"dashboard_{instance.user.id}",
            f"vcf_section_{instance.user.id}"
        ]
        cache.delete_many(cache_keys)


@receiver(post_delete, sender=UserPurchase)
def invalidate_vcf_cache_on_purchase_delete(sender, instance, **kwargs):
    """Invalidate VCF tabs cache when user purchase is deleted"""
    cache_keys = [
        f"vcf_tabs_{instance.user.id}",
        f"dashboard_{instance.user.id}",
        f"vcf_section_{instance.user.id}"
    ]
    cache.delete_many(cache_keys)


@receiver(post_save, sender=VCFFile)
def invalidate_all_vcf_caches_on_vcf_change(sender, instance, **kwargs):
    """Invalidate all VCF tabs caches when VCF file changes"""
    # Get all user IDs that have purchases
    user_ids = UserPurchase.objects.values_list('user_id', flat=True).distinct()
    
    # Delete cache for all users
    cache_keys = [f"vcf_tabs_{user_id}" for user_id in user_ids]
    cache.delete_many(cache_keys)


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