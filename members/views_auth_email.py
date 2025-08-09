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
def member_settings(request):
    return render(request, 'members/member_settings.html')

@login_required
def update_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if new_password != confirm_password:
            messages.error(request, 'New password and confirm password do not match.')
            return redirect('members:member_settings')
        
        user = request.user
        if not user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return redirect('members:member_settings')
        
        # Update password
        user.password = make_password(new_password)
        user.save()
        
        messages.success(request, 'Password updated successfully!')
        return redirect('members:member_settings')
    
    return render(request, 'members/update_password.html')

@login_required
def purchase_history(request):
    purchases = UserPurchase.objects.filter(user=request.user).order_by('-date_purchased')
    return render(request, 'members/purchase_history.html', {'purchases': purchases})

@login_required
def download_vcf(request, file_id):
    vcf_file = get_object_or_404(VCFFile, id=file_id, user=request.user)
    file_path = vcf_file.file.path
    
    if not os.path.exists(file_path):
        raise Http404("File does not exist.")
    
    response = FileResponse(open(file_path, 'rb'), content_type='text/vcard')
    response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
    return response

@login_required
def contact_support(request):
    if request.method == 'POST':
        subject = request.POST.get('subject')
        message = request.POST.get('message')
        
        # Here you can add logic to save the message to the database or send an email
        Contact.objects.create(
            user=request.user,
            subject=subject,
            message=message
        )
        
        messages.success(request, 'Your message has been sent to support.')
        return redirect('members:member_settings')
    
    return render(request, 'members/contact_support.html')
