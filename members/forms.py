from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import MemberAccount, MemberProfile
import json

class MemberRegisterForm(UserCreationForm):
    # Load country codes from JSON
    with open('members/country-codes.json') as f:
        COUNTRIES = [(c['dial_code'], f"{c['name']} {c['dial_code']}") 
                    for c in json.load(f)]
    
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
            'placeholder': 'Phone number without country code'
        })
    )
    
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
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 rounded border border-gray-300',
            'placeholder': 'Mobile number or username'
        })
    )
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