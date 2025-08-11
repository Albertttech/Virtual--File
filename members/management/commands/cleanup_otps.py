# In management/commands/cleanup_otps.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from members.models import EmailVerificationOTP

class Command(BaseCommand):
    help = 'Clean up expired OTPs'

    def handle(self, *args, **options):
        expired = EmailVerificationOTP.objects.filter(
            expires_at__lt=timezone.now()
        )
        count = expired.count()
        expired.delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {count} expired OTPs'))