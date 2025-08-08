import os
import uuid
import requests
import hmac
import hashlib
import json
import logging
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model, authenticate, login, logout, update_session_auth_hash
from django.http import FileResponse, Http404, JsonResponse, HttpResponse
from django.urls import reverse
from django.db import IntegrityError
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.db import models, IntegrityError

from .models import VCFFile, UserPurchase, MemberAccount, EmailVerificationOTP
from .forms import MemberRegisterForm, MemberLoginForm, AuthenticationEmailForm, UpdateAuthEmailForm, VerifyEmailOTPForm
from common.decorators import member_required
from customadmin.models import Contact

@login_required
def update_auth_email(request):
    print('DEBUG: Entered update_auth_email view')
    print(f'DEBUG: Request method: {request.method}')
    if request.method == 'POST':
        print(f'DEBUG: POST data: {request.POST}')
        # For now, just render the update_auth_email.html page
        return render(request, 'members/update_auth_email.html')
    return render(request, 'members/update_auth_email.html')

@login_required
def verify_email_otp(request):
    new_email = request.session.get('new_auth_email')
    if not new_email:
        messages.error(request, 'Email verification session expired. Please try again.')
        return redirect('members:member_settings')
    
    if request.method == 'POST':
        form = VerifyEmailOTPForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            try:
                # Verify OTP
                otp = EmailVerificationOTP.objects.get(
                    user=request.user,
                    new_email=new_email,
                    is_used=False
                )
                
                if otp.is_valid() and otp.code == otp_code:
                    # Update email
                    request.user.authentication_email = new_email
                    request.user.save()
                    
                    # Mark OTP as used
                    otp.is_used = True
                    otp.save()
                    
                    # Clear session
                    del request.session['new_auth_email']
                    
                    messages.success(request, 'Email updated successfully!')
                    return redirect('members:member_settings')
                else:
                    messages.error(request, 'Invalid or expired verification code.')
            except EmailVerificationOTP.DoesNotExist:
                messages.error(request, 'Verification code not found or expired.')
    else:
        form = VerifyEmailOTPForm()
    
    return render(request, 'members/update_auth_email.html', {
        'form': form,
        'new_email': new_email
    })

@login_required
def resend_otp(request):
    new_email = request.GET.get('email') or request.session.get('new_auth_email')
    if not new_email:
        messages.error(request, 'Email not found. Please try again.')
        return redirect('members:member_settings')
    
    # Generate and save new OTP
    otp = EmailVerificationOTP.objects.create_otp(
        user=request.user,
        new_email=new_email
    )
    
    # Send OTP email
    subject = 'Email Verification Code'
    message = f'Your verification code is: {otp.code}\nThis code will expire in 5 minutes.'
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [new_email],
            fail_silently=False,
        )
        request.session['new_auth_email'] = new_email
        messages.success(request, 'New verification code sent!')
    except Exception as e:
        logging.error(f"Failed to send OTP email: {str(e)}")
        messages.error(request, 'Failed to send verification code. Please try again.')
    
    return redirect('members:verify_email_otp')

@csrf_exempt
def stub_auth_email(request):
    if request.method == 'POST':
        return JsonResponse({
            'success': True,
            'redirect_url': '/settings/'
        })
    return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)
