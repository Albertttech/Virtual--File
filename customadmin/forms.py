from django import forms
from .models import VCFFile, Contact
import json
import os

# Load country codes

# Use the shared country-codes.json in common/static
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_PATH = os.path.join(BASE_DIR, 'common', 'static', 'country-codes.json')

with open(JSON_PATH, encoding='utf-8') as f:
    COUNTRY_CODES = json.load(f)

COUNTRY_CHOICES = [(c['dial_code'], f"{c['name']} ({c['dial_code']})") for c in COUNTRY_CODES]


class VCFFileForm(forms.ModelForm):
    class Meta:
        model = VCFFile
        fields = ['name', 'max_contacts']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Enter file name'}),
            'max_contacts': forms.NumberInput(attrs={'min': 1}),
        }


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
