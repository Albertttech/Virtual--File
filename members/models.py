from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.conf import settings
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
    mobile_number = models.CharField(max_length=20, unique=True)
    country_code = models.CharField(max_length=5)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    objects = MemberAccountManager()
    
    USERNAME_FIELD = 'mobile_number'
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
        related_name='user_purchases'  # Consistent naming
    )
    vcf_file = models.ForeignKey(
        'customadmin.VCFFile',
        on_delete=models.CASCADE,
        related_name='file_purchases'  # More explicit name
    )
    payment_reference = models.CharField(max_length=100, unique=True)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    verification_attempts = models.IntegerField(default=0)
    last_verification = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ('user', 'vcf_file')  # One purchase per user per VCF
        verbose_name = 'User Purchase'
        verbose_name_plural = 'User Purchases'
    
    def __str__(self):
        return f"{self.user} - {self.vcf_file} (${self.amount_paid})"