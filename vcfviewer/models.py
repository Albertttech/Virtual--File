from django.db import models

class VCFFile(models.Model):
    VCF_TYPE_CHOICES = [
        ('free', 'Free'),
        ('premium', 'Premium'),
    ]
    name = models.CharField(max_length=100, unique=True)
    vcf_type = models.CharField(max_length=10, choices=VCF_TYPE_CHOICES, default='free')
    max_contacts = models.PositiveIntegerField(null=True, blank=True)
    unlimited_contacts = models.BooleanField(default=False)
    subscription_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
  
class Contact(models.Model):
    vcf_file = models.ForeignKey(VCFFile, on_delete=models.CASCADE, related_name='contacts')
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)

    class Meta:
        unique_together = ('vcf_file', 'phone')

    def __str__(self):
        return f"{self.name} ({self.phone})"
