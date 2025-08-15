from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import random
import string
from customadmin.models import VCFFile
from django.contrib import admin
from django.utils.functional import cached_property  # Add this import

class MemberAccountManager(BaseUserManager):
    def create_user(self, mobile_number, country_code, username, password=None, **extra_fields):
        if not mobile_number:
            raise ValueError('Users must have a mobile number')
        if not country_code:
            raise ValueError('Users must have a country code')

        user = self.model(
            mobile_number=mobile_number,
            country_code=country_code,
            username=username,
            **extra_fields
        )
        user.set_password(password)
        
        # Set initial auth_email_last_changed to allow immediate email change
        user.auth_email_last_changed = timezone.now() - timedelta(days=getattr(settings, 'AUTH_EMAIL_CHANGE_INTERVAL', 30))
        
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile_number, country_code, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(mobile_number, country_code, username, password, **extra_fields)


class MemberAccount(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)
    mobile_number = models.CharField(
        max_length=11,
        unique=True,
        help_text="Local number only, without country code (8-11 digits)."
    )
    country_code = models.CharField(max_length=5)
    phone_number = models.CharField(
        max_length=20,
        unique=True,
        editable=False,
        blank=True,
        null=True
    )
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_authenticated = models.BooleanField(default=False)
    authentication_email = models.EmailField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name="Authentication Email"
    )
    
    auth_email_last_changed = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Last Authentication Email Change"
    )
    objects = MemberAccountManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['username', 'country_code']

    class Meta:
        verbose_name = _('Member Account')
        verbose_name_plural = _('Member Accounts')

    def __str__(self):
        return self.username

    def get_full_name(self):
        try:
            return f"{self.profile.first_name} {self.profile.last_name}".strip() or self.username
        except:
            return self.username

    def get_short_name(self):
        try:
            return self.profile.first_name or self.username
        except:
            return self.username

    def clean(self):
        # Validate mobile number
        if not self.mobile_number or not self.mobile_number.isdigit():
            raise ValidationError({'mobile_number': 'Mobile number must contain only digits.'})
        if not (8 <= len(self.mobile_number) <= 11):
            raise ValidationError({'mobile_number': 'Mobile number must be between 8 and 11 digits.'})
        if not self.country_code:
            raise ValidationError({'country_code': 'Country code is required.'})

        # Store full phone number
        self.phone_number = f"{self.country_code}{self.mobile_number}"

        # Normalize authentication email
        if self.authentication_email:
            self.authentication_email = self.authentication_email.lower().strip()

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
        
    # ====================== CACHED PROPERTIES ======================
    @cached_property
    def cached_authentication_email(self):
        """Cached authentication email to avoid repeated DB lookups"""
        return self.authentication_email
    
    @cached_property
    def cached_purchases(self):
        """Cached list of active purchases to minimize DB queries"""
        return list(self.user_purchases.filter(
            is_verified=True,
            is_active=True
        ).select_related('vcf_file').only('vcf_file_id', 'vcf_file__name'))
    
    @cached_property
    def cached_profile(self):
        """Cached profile object with safe handling for missing profile"""
        try:
            return self.profile
        except MemberProfile.DoesNotExist:
            return None
    
    @cached_property
    def cached_mobile_number(self):
        """Cached mobile number with fallback to username"""
        return self.mobile_number or self.username
    # ====================== END CACHED PROPERTIES ======================


class MemberProfile(models.Model):
    account = models.OneToOneField(
        MemberAccount,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    email = models.EmailField(max_length=255, blank=True, null=True)
    include_email_in_vcf = models.BooleanField(default=True)
    profile_name = models.CharField(max_length=100, blank=True)
    contact_name = models.CharField(max_length=100, blank=True)
    address = models.CharField(max_length=150, blank=True)   
    city = models.CharField(max_length=100, blank=True) 
    postal_code = models.CharField(max_length=20, blank=True)
    about_me = models.TextField(blank=True)
    profile_picture = models.ImageField(
        upload_to='profile_pics/',
        blank=True,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.account.mobile_number}"


class UserPurchase(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_purchases'
    )
    vcf_file = models.ForeignKey(
        VCFFile,
        on_delete=models.CASCADE,
        related_name='file_purchases'
    )
    payment_reference = models.CharField(max_length=100, unique=True)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    verification_attempts = models.IntegerField(default=0)
    last_verification = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'vcf_file')
        verbose_name = 'User Purchase'
        verbose_name_plural = 'User Purchases'
        indexes = [
            models.Index(fields=['vcf_file'], name='purchase_vcf_file_idx'),
            models.Index(fields=['is_verified', 'is_active'], name='purchase_verified_active_idx'),
        ]

    def __str__(self):
        return f"{self.user} - {self.vcf_file} (${self.amount_paid})"


class EmailVerificationOTP(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    objects = models.Manager()
    
    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at
    
    class Meta:
        verbose_name = "Email Verification OTP"
        verbose_name_plural = "Email Verification OTPs"
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        # Normalize email before saving
        self.email = self.email.lower().strip()
        super().save(*args, **kwargs)


class FirstNameLastName(models.Model):
    user = models.OneToOneField('MemberAccount', on_delete=models.CASCADE, related_name='first_last_name')
    first_name = models.CharField(max_length=150, blank=True, default='')
    last_name = models.CharField(max_length=150, blank=True, default='')

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


admin.site.register(FirstNameLastName)