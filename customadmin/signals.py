# customadmin/signals.py
from django.contrib.auth.models import User
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.conf import settings
from decouple import config

@receiver(post_migrate)
def create_admin_user(sender, **kwargs):
    if not User.objects.filter(username=settings.SUPERUSER_USERNAME).exists():
        User.objects.create_superuser(
            username=settings.SUPERUSER_USERNAME,
            email=settings.SUPERUSER_EMAIL,
            password=settings.SUPERUSER_PASSWORD
        )