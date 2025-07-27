from django import forms
from .models import VCFFile, Contact
import json
import os

# Load country codes
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(BASE_DIR, 'static', 'vcfviewer', 'CountryCodes.json')

with open(JSON_PATH, encoding='utf-8') as f:
    COUNTRY_CODES = json.load(f)

COUNTRY_CHOICES = [(c['dial_code'], f"{c['name']} ({c['dial_code']})") for c in COUNTRY_CODES]



class VCFFileForm(forms.ModelForm):
    class Meta:
        model = VCFFile
        fields = ['name', 'vcf_type', 'max_contacts', 'unlimited_contacts', 'subscription_price']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Enter file name'}),
            'vcf_type': forms.Select(attrs={'id': 'id_vcf_type'}),
            'max_contacts': forms.NumberInput(attrs={'min': 1}),
            'subscription_price': forms.NumberInput(attrs={'min': 0, 'step': '0.01'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        vcf_type = cleaned_data.get('vcf_type')
        max_contacts = cleaned_data.get('max_contacts')
        unlimited = cleaned_data.get('unlimited_contacts')
        price = cleaned_data.get('subscription_price')

        if vcf_type == 'free':
            if not max_contacts:
                self.add_error('max_contacts', 'Max contacts is required for free VCF.')
            cleaned_data['subscription_price'] = None
            cleaned_data['unlimited_contacts'] = False
        elif vcf_type == 'premium':
            if not unlimited and not max_contacts:
                self.add_error('max_contacts', 'Specify max contacts or select unlimited.')
            if price is None:
                self.add_error('subscription_price', 'Subscription price is required for premium VCF.')
        return cleaned_data


class ContactForm(forms.Form):
    name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'placeholder': 'Contact Name'})
    )
    country_code = forms.ChoiceField(choices=COUNTRY_CHOICES)
    phone = forms.CharField(
        max_length=20,
        widget=forms.TextInput(attrs={'placeholder': 'Phone Number'})
    )


class VCFUploadForm(forms.Form):
    vcf_file = forms.FileField(label='Select a .vcf file')
