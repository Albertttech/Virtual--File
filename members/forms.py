from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import MemberAccount, MemberProfile, EmailVerificationOTP
import json
import re

class UpdateAuthEmailForm(forms.Form):
    auth_email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'bg-slate-800 text-white rounded-lg px-4 py-2 w-full',
        'placeholder': 'Enter authentication email'
    }))

class VerifyEmailOTPForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'bg-slate-800 text-white rounded-lg px-4 py-2 w-full',
            'placeholder': 'Enter 6-digit code'
        })
    )

    def clean_otp_code(self):
        otp = self.cleaned_data['otp_code']
        if not otp.isdigit():
            raise forms.ValidationError("OTP must contain only digits")
        return otp

class MemberRegisterForm(UserCreationForm):
    # Load and sort country codes
    with open('members/country-codes.json') as f:
        countries_raw = json.load(f)
        
        # Sort by country name
        countries_sorted = sorted(countries_raw, key=lambda c: c['name'].lower())

        # Create choices: (dial_code, "Country Name +dial_code")
        COUNTRIES = [
            (c['dial_code'], f"{c['name']:<22} {c['dial_code']}")
            for c in countries_sorted
        ]
    
    country_code = forms.ChoiceField(
        choices=COUNTRIES,
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300',
            'id': 'country-code-select'
        })
    )
    
    mobile_number = forms.CharField(
        max_length=20,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300',
            'placeholder': '8-digit phone number (without country code)'
        })
    )
    def clean_mobile_number(self):
        mobile = self.cleaned_data.get('mobile_number', '')
        if not mobile.isdigit():
            raise forms.ValidationError('Mobile number must contain only digits.')
        if not 8 <= len(mobile) <= 11:
            raise forms.ValidationError('Mobile number must be between 8 and 11 digits.')
        return mobile
    
    def clean(self):
        cleaned_data = super().clean()
        country_code = cleaned_data.get('country_code', '')
        mobile = cleaned_data.get('mobile_number', '')
        if country_code and mobile:
            cleaned_data['phone_number'] = f"{country_code}{mobile}"
        return cleaned_data
    
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300'
        })
    )
    
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300'
        })
    )

    class Meta:
        model = MemberAccount
        fields = ('country_code', 'mobile_number', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'username' in self.fields:
            self.fields['username'].required = False
            self.fields['username'].widget = forms.HiddenInput()

    def clean_username(self):
        # Always return a dummy value, actual username is set in the view
        return self.cleaned_data.get('username', '')

class MemberLoginForm(AuthenticationForm):
    username = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300',
            'placeholder': 'Country code + mobile number (e.g. +2348012345678)',
            'maxlength': '30'
        })
    )

    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        # Enforce country code + 8 digits
        if not re.match(r'^\+\d{1,4}\d{8,11}$', username):
            raise forms.ValidationError('Enter your full number in international format (e.g. +2348137458481)')

        return username
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300',
            'placeholder': 'Password'
        })
    )

class MemberProfileForm(forms.ModelForm):
    class Meta:
        model = MemberProfile
        fields = ('first_name', 'last_name', 'email', 'contact_name', 'profile_picture')

class AuthenticationEmailForm(forms.ModelForm):
    class Meta:
        model = MemberAccount
        fields = ['authentication_email']
        widgets = {
            'authentication_email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your authentication email',
            }),
        }
        labels = {
            'authentication_email': 'Authentication Email',
        }

