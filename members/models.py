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
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile_number, country_code, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(mobile_number, country_code, username, password, **extra_fields)


class MemberAccount(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)

    # Allow mobile number to be saved separately
    mobile_number = models.CharField(
        max_length=11,
        unique=True,
        help_text="Local number only, without country code (8-11 digits)."
    )

    country_code = models.CharField(max_length=5)

    # phone_number should store country_code + mobile_number.
    # Ensure max_length is large enough and enforce uniqueness.
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
    authentication_email = models.EmailField(max_length=255, blank=True, null=True)

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
        # Validate mobile number: digits only, 8–11 digits
        if not self.mobile_number or not self.mobile_number.isdigit():
            raise ValidationError({'mobile_number': 'Mobile number must contain only digits.'})
        if not (8 <= len(self.mobile_number) <= 11):
            raise ValidationError({'mobile_number': 'Mobile number must be between 8 and 11 digits.'})
        if not self.country_code:
            raise ValidationError({'country_code': 'Country code is required.'})

        # Store full phone number in E.164 style: +<country_code><mobile_number>
        self.phone_number = f"{self.country_code}{self.mobile_number}"

    def save(self, *args, **kwargs):
        self.full_clean()  # Triggers clean()
        super().save(*args, **kwargs)


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

    def __str__(self):
        return f"{self.user} - {self.vcf_file} (${self.amount_paid})"


class EmailVerificationOTPManager(models.Manager):
    def create_otp(self, user, email):
        """Create and return a new OTP for the given user and email."""
        otp = self.model(
            user=user,
            email=email,
            otp_code=''.join(random.choices(string.digits, k=6)),
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        otp.save(using=self._db)
        return otp


class EmailVerificationOTP(models.Model):
    user = models.ForeignKey(
        MemberAccount,
        on_delete=models.CASCADE,
        related_name='email_otps'
    )
    email = models.EmailField(max_length=255)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    objects = EmailVerificationOTPManager()

    def save(self, *args, **kwargs):
        if not self.otp_code:
            # Generate 6-digit OTP
            self.otp_code = ''.join(random.choices(string.digits, k=6))
        if not self.expires_at:
            # Set expiry to 5 minutes from creation
            self.expires_at = timezone.now() + timedelta(minutes=5)
        super().save(*args, **kwargs)

    def is_valid(self):
        return (
            not self.is_used and 
            timezone.now() <= self.expires_at
        )

    class Meta:
        ordering = ['-created_at']
