from django.db import models
from django.conf import settings

class VCFFile(models.Model):
    VCF_TYPE_CHOICES = [
        ('free', 'Free'),
        ('premium', 'Premium'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    vcf_type = models.CharField(max_length=10, choices=VCF_TYPE_CHOICES, default='free')
    file = models.FileField(upload_to='vcfs/', blank=True, null=True)
    max_contacts = models.PositiveIntegerField(null=True, blank=True)
    unlimited_contacts = models.BooleanField(default=False)
    subscription_price = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    hidden = models.BooleanField(default=False)

    def __str__(self):
        return self.name
    # Add this to the VCFFile model in customadmin/models.py
    def is_purchased_by(self, user):
        """Check if this VCF file has been purchased by the given user"""
        return self.file_purchases.filter(
            user=user,
            is_verified=True,
            is_active=True
        ).exists()

class Contact(models.Model):
    vcf_file = models.ForeignKey(VCFFile, on_delete=models.CASCADE, related_name='contacts')
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)

    class Meta:
        unique_together = ('vcf_file', 'phone')

    def __str__(self):
        return f"{self.name} ({self.phone})"
