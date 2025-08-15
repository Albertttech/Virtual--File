# members/tasks.py
from celery import shared_task
from django.core.cache import cache
from paystackapi.transaction import Transaction
from .models import UserPurchase
from .views import get_paystack_credentials
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def verify_paystack_payment_async(self, purchase_id):
    """
    Asynchronous task to verify Paystack payment
    """
    try:
        purchase = UserPurchase.objects.get(id=purchase_id)
        
        if purchase.is_verified:
            return {"status": "already_verified", "purchase_id": purchase_id}
        
        credentials = get_paystack_credentials()
        
        # Verify with Paystack
        response = Transaction.verify(
            reference=purchase.payment_reference,
            authorization_key=credentials['secret_key']
        )
        
        if response['status'] and response['data']['status'] == 'success':
            purchase.is_verified = True
            purchase.verification_attempts += 1
            purchase.save()
            
            # Invalidate user's VCF cache
            cache_key = f"vcf_tabs_{purchase.user.id}"
            cache.delete(cache_key)
            
            logger.info(f"Payment verified successfully for purchase {purchase_id}")
            return {
                "status": "verified", 
                "purchase_id": purchase_id,
                "amount": str(purchase.amount_paid)
            }
        else:
            purchase.verification_attempts += 1
            purchase.save()
            
            # Retry if verification failed and we haven't exceeded max retries
            if self.request.retries < self.max_retries:
                logger.warning(f"Payment verification failed for purchase {purchase_id}, retrying...")
                raise self.retry(countdown=60 * (self.request.retries + 1))
            
            logger.error(f"Payment verification failed permanently for purchase {purchase_id}")
            return {"status": "failed", "purchase_id": purchase_id}
            
    except UserPurchase.DoesNotExist:
        logger.error(f"Purchase {purchase_id} not found")
        return {"status": "error", "message": "Purchase not found"}
    
    except Exception as exc:
        logger.error(f"Error verifying payment for purchase {purchase_id}: {str(exc)}")
        
        # Retry on unexpected errors
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))
        
        return {"status": "error", "message": str(exc)}


@shared_task
def cleanup_unverified_purchases():
    """
    Cleanup task to remove old unverified purchases
    """
    from django.utils import timezone
    from datetime import timedelta
    
    # Remove purchases older than 24 hours that are still unverified
    cutoff_time = timezone.now() - timedelta(hours=24)
    
    deleted_count = UserPurchase.objects.filter(
        is_verified=False,
        created_at__lt=cutoff_time,
        verification_attempts__gte=5
    ).delete()[0]
    
    logger.info(f"Cleaned up {deleted_count} unverified purchases")
    return {"deleted_count": deleted_count}


@shared_task
def invalidate_user_cache(user_id):
    """
    Task to invalidate user-specific caches
    """
    cache_keys = [
        f"vcf_tabs_{user_id}",
        f"dashboard_{user_id}",
        f"vcf_section_{user_id}",
    ]
    
    cache.delete_many(cache_keys)
    logger.info(f"Invalidated cache for user {user_id}")
    return {"status": "success", "user_id": user_id}
