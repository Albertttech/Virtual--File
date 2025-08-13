import os
import uuid
import requests
import hmac
import hashlib
import json
import logging
import random
from datetime import timedelta

from django.contrib.auth import update_session_auth_hash
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model, authenticate, login, logout, update_session_auth_hash
from django.http import FileResponse, Http404, JsonResponse, HttpResponse
from django.urls import reverse
from django.db import IntegrityError, models
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.views import PasswordResetView

from .models import VCFFile, UserPurchase, MemberAccount, EmailVerificationOTP
from .forms import MemberRegisterForm, MemberLoginForm
from common.decorators import member_required
from customadmin.models import Contact
from members.utils.email_otp import create_and_send_email_otp
from .middleware import auth_email_required

# =================================================================
# Categories in this file:
# 1. Authentication Views (Login, Register, Password Reset)
# 2. Payment & Subscription Views (Paystack Integration)
# 3. VCF File Management Views
# 4. User Profile & Settings Views
# 5. Email Authentication Views
# 6. Helper Functions
# =================================================================

# Password reset view (email-based)
# =================================================================
# 1. Authentication Views
# =================================================================

def member_register(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            logout(request)
        else:
            return redirect('members:dashboard')

    if request.method == 'POST':
        form = MemberRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            mobile = form.cleaned_data['mobile_number']
            country_code = form.cleaned_data['country_code']
            phone_number = f"{country_code}{mobile}"
            user.username = phone_number
            user.phone_number = phone_number
            user.is_staff = False
            user.save()
            login(request, user)
            messages.success(request, "Registration successful! You are now logged in.")
            return redirect('members:dashboard')
    else:
        form = MemberRegisterForm()
    
    return render(request, 'members/authentication/register.html', {'form': form})

def member_login(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            logout(request)
        else:
            # Force database query to check auth email
            user = MemberAccount.objects.get(id=request.user.id)
            if not user.authentication_email:
                messages.warning(request, "Authentication email required. Please set it in settings to continue.")
                return redirect('members:member_settings')
            return redirect('members:dashboard')

    error = None
    if request.method == 'POST':
        form = MemberLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            if user.is_staff:
                error = "Admins cannot log in here. Please use the admin portal."
            else:
                login(request, user)
                messages.success(request, "Login successful!")
                # Force check auth email after login
                if not user.authentication_email:
                    messages.warning(request, "Authentication email required. Please set it in settings to continue.")
                    return redirect('members:member_settings')
                return redirect('members:dashboard')
        else:
            error = "Invalid credentials."
    else:
        form = MemberLoginForm()

    return render(request, 'members/authentication/login.html', {
        'form': form,
        'error': error
    })

def member_logout(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('members:login')

class MemberPasswordResetView(PasswordResetView):
    template_name = 'members/password_reset_form.html'
    email_template_name = 'members/password_reset_email.html'
    subject_template_name = 'members/password_reset_subject.txt'
    success_url = '/members/password-reset/done/'

def forgot_password(request):
    username = request.GET.get('username', '')
    return render(request, 'members/authentication/forgot_password.html', {'username': username})

def reset_password(request):
    username = request.GET.get('username', '')  # Get username from query params for GET request
    
    if not username:
        messages.error(request, 'Username is required')
        return redirect('members:authentication/forgot_password')
        
    # Check if user exists before showing the form
    User = get_user_model()
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, 'User not found')
        return redirect('members:authentication/forgot_password')
    
    if request.method == 'POST':
        username = request.POST.get('username', '')
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        if not all([username, new_password, confirm_password]):
            messages.error(request, 'All fields are required')
        elif new_password != confirm_password:
            messages.error(request, 'Passwords do not match')
        else:
            try:
                user = User.objects.get(username=username)
                user.set_password(new_password)  # Using set_password instead of make_password
                user.save()
                messages.success(request, 'Password reset successful. Please log in.')
                return redirect('members:authentication/login')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
    
    return render(request, 'members/authentication/reset_password.html', {'username': username})

# =================================================================
# 2. Payment & Subscription Views (Paystack Integration)
# =================================================================

@auth_email_required
def get_paystack_credentials():
    """Safe method to get Paystack credentials with multiple fallbacks"""
    if settings.TEST_MODE:
        return {
            'secret_key': settings.PAYSTACK_SECRET_KEY,
            'public_key': settings.PAYSTACK_PUBLIC_KEY,
            'success_url': settings.PAYSTACK_SUCCESS_URL
            }
    
    try:
        secret_key = settings.PAYSTACK_SECRET_KEY
        public_key = settings.PAYSTACK_PUBLIC_KEY
        success_url = settings.PAYSTACK_SUCCESS_URL
    except AttributeError:
        try:
            # 2. Try direct import from settings
            from vcfproject.settings import PAYSTACK_SECRET_KEY as secret_key
            from vcfproject.settings import PAYSTACK_PUBLIC_KEY as public_key
            from vcfproject.settings import PAYSTACK_SUCCESS_URL as success_url
        except ImportError:
            # 3. Fallback to environment variables
            secret_key = os.getenv('PAYSTACK_SECRET_KEY', '')
            public_key = os.getenv('PAYSTACK_PUBLIC_KEY', '')
            success_url = os.getenv('PAYSTACK_SUCCESS_URL', 'http://127.0.0.1:8000/vcf-tabs/')
    
    return {
        'secret_key': secret_key.strip(),
        'public_key': public_key.strip(),
        'success_url': success_url.strip()
    }

def test_paystack_connection(request):
    credentials = get_paystack_credentials()
    headers = {
        'Authorization': f'Bearer {credentials["secret_key"]}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(
            'https://api.paystack.co/transaction/totals',
            headers=headers
        )
        return JsonResponse({
            'status': response.status_code == 200,
            'response': response.json(),
            'key_used': credentials["secret_key"][:8] + "..."  # Show first 8 chars
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@member_required
@auth_email_required
def test_payment(request, vcf_id):
    if not settings.TEST_MODE:
        raise Http404("Test mode only available when TEST_MODE=True")
    
    vcf = get_object_or_404(VCFFile, id=vcf_id)
    
    # Create or update purchase record
    purchase, created = UserPurchase.objects.get_or_create(
        user=request.user,
        vcf_file=vcf,
        defaults={
            'payment_reference': "TEST_REF_" + str(uuid.uuid4())[:8],
            'amount_paid': vcf.subscription_price,
            'is_verified': True  # Critical for test purchases
        }
    )
    
    if not created:
        purchase.is_verified = True
        purchase.save()
    
    messages.success(request, "Test purchase completed successfully")
    return redirect(reverse('members:vcf_tabs'))

@csrf_exempt
def paystack_webhook(request):
    if request.method == 'POST':
        payload = request.body
        signature = request.headers.get('X-Paystack-Signature')
        
        # Verify the signature
        secret = get_paystack_credentials()['secret_key']
        computed_signature = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha512
        ).hexdigest()
        
        if computed_signature != signature:
            return HttpResponse(status=400)
        
        event = json.loads(payload)
        print(f"Paystack webhook received: {event}")
        
        # Handle different event types
        if event['event'] == 'charge.success':
            # Process successful payment
            data = event['data']
            reference = data['reference']
            
            # Verify and process the payment
            return verify_payment(request, reference)
            
        return HttpResponse(status=200)
    return HttpResponse(status=405)

@member_required
@auth_email_required
def initiate_payment(request, vcf_id):
    credentials = get_paystack_credentials()
    vcf = get_object_or_404(VCFFile, id=vcf_id, vcf_type='premium', hidden=False)

    if request.method == 'POST':
        email = request.POST.get('email', f"{request.user.username}@vcfapp.com")
        amount = int(float(vcf.subscription_price) * 100)  # Convert Naira to kobo

        headers = {
            'Authorization': f'Bearer {credentials["secret_key"]}',
            'Content-Type': 'application/json'
        }

        payload = {
            'email': email,
            'amount': amount,
            'callback_url': credentials['success_url'],
            'metadata': {
                'user_id': request.user.id,
                'vcf_file_id': vcf.id,
                'custom_fields': [
                    {
                        'display_name': "VCF File",
                        'variable_name': "vcf_file",
                        'value': vcf.name
                    }
                ]
            }
        }

        try:
            response = requests.post(
                'https://api.paystack.co/transaction/initialize',
                headers=headers,
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                auth_url = data.get('authorization_url')
                if auth_url:
                    return redirect(auth_url)
                else:
                    messages.error(request, "Could not retrieve payment link. Try again.")
            else:
                error_msg = response.json().get('message', 'Unknown error')
                messages.error(request, f"Payment failed: {error_msg}")

        except requests.exceptions.RequestException as e:
            messages.error(request, f"Network error: {str(e)}")

        return render(request, 'payment/failed.html')

    # If GET request, show the form
    return render(request, 'payment/payment_form.html', {
        'vcf': vcf,
        'public_key': credentials['public_key'],
        'amount': vcf.subscription_price
    })

@member_required
def payment_complete(request):
    reference = request.GET.get('reference')
    if reference:
        return verify_payment(request, reference)
    messages.error(request, "Missing payment reference")
    return redirect('members:vcf_tabs')

@member_required
def verify_payment(request, reference):
    print(f"\n=== Starting payment verification for reference: {reference} ===")
    User = get_user_model()
    credentials = get_paystack_credentials()

    try:
        # 1. Verify with Paystack
        headers = {
            'Authorization': f'Bearer {credentials["secret_key"]}',
            'Content-Type': 'application/json',
        }
        print("Making request to Paystack API...")
        response = requests.get(
            f'https://api.paystack.co/transaction/verify/{reference}',
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        print(f"Paystack response: {json.dumps(data, indent=2)}")

        if not data.get('status'):
            print("Paystack returned unsuccessful status")
            messages.error(request, "Payment verification failed with Paystack")
            return redirect('members:vcf_tabs')

        tx = data['data']
        if tx['status'] != 'success':
            print(f"Transaction status is {tx['status']}, not 'success'")
            messages.error(request, f"Payment status: {tx['status']}")
            return redirect('members:vcf_tabs')

        # 2. Extract metadata with fallbacks
        metadata = tx.get('metadata', {})
        print(f"Raw metadata: {metadata}")
        
        user_id = metadata.get('user_id', request.user.id)
        vcf_id = metadata.get('vcf_file_id', request.GET.get('vcf_id'))
        
        if not vcf_id:
            print("No vcf_id found in metadata or GET parameters")
            messages.error(request, "Missing VCF file information in payment")
            return redirect('members:vcf_tabs')

        print(f"Extracted user_id: {user_id}, vcf_id: {vcf_id}")

        # 3. Get user and VCF file
        try:
            user = User.objects.get(id=user_id)
            vcf = VCFFile.objects.get(id=vcf_id)
            print(f"Found user: {user.username}, VCF: {vcf.name}")
        except User.DoesNotExist:
            print(f"User with id {user_id} does not exist")
            messages.error(request, "User account not found")
            return redirect('members:vcf_tabs')
        except VCFFile.DoesNotExist:
            print(f"VCF with id {vcf_id} does not exist")
            messages.error(request, "VCF file not found")
            return redirect('members:vcf_tabs')

        # 4. Create/update purchase record
        print("Creating/updating purchase record...")
        purchase, created = UserPurchase.objects.update_or_create(
            user=user,
            vcf_file=vcf,
            defaults={
                'payment_reference': reference,
                'amount_paid': float(tx['amount']) / 100,
                'is_verified': True,
                'is_active': True
            }
        )
        print(f"{'Created' if created else 'Updated'} purchase record:")
        print(f"ID: {purchase.id}")
        print(f"User: {purchase.user.username}")
        print(f"VCF: {purchase.vcf_file.name} (ID: {purchase.vcf_file.id})")
        print(f"Verified: {purchase.is_verified}")
        print(f"Active: {purchase.is_active}")

        # 5. Verify the record exists in database
        try:
            db_purchase = UserPurchase.objects.get(payment_reference=reference)
            print("Database verification successful - record exists")
        except UserPurchase.DoesNotExist:
            print("WARNING: Record not found in database after creation!")

        messages.success(request, "Payment verified successfully! You can now access the VCF file.")
        return redirect('members:vcf_tabs')

    except requests.exceptions.RequestException as e:
        print(f"Network error: {str(e)}")
        messages.error(request, "Network error verifying payment. Please check your purchase history.")
    except Exception as e:
        print(f"Unexpected error: {str(e)}", exc_info=True)
        messages.error(request, f"An unexpected error occurred: {str(e)}")
    
    return redirect('members:vcf_tabs')

@member_required
def check_vcf_access(request, vcf_id):
    try:
        vcf = VCFFile.objects.get(id=vcf_id)
        has_access = request.user.user_purchases.filter(
            vcf_file=vcf,
            is_verified=True,
            is_active=True
        ).exists()
        
        purchases = request.user.user_purchases.filter(vcf_file=vcf)
        
        return JsonResponse({
            'vcf_id': vcf_id,
            'vcf_name': vcf.name,
            'has_access': has_access,
            'purchases': [{
                'id': p.id,
                'reference': p.payment_reference,
                'verified': p.is_verified,
                'active': p.is_active,
                'date': p.created_at.isoformat()
            } for p in purchases]
        })
    except VCFFile.DoesNotExist:
        return JsonResponse({'error': 'VCF not found'}, status=404)

        
@member_required
def debug_purchases(request):
    purchases = request.user.user_purchases.select_related('vcf_file').all()
    data = {
        'user': request.user.username,
        'purchases': [
            {
                'vcf_id': p.vcf_file.id,
                'vcf_name': p.vcf_file.name,
                'reference': p.payment_reference,
                'verified': p.is_verified,
                'active': p.is_active,
                'date': p.created_at
            } for p in purchases
        ]
    }
    return JsonResponse(data)


@member_required
def check_payment_status(request):
    reference = request.GET.get('reference')
    if not reference:
        return JsonResponse({'error': 'Missing reference'}, status=400)
    
    purchase = UserPurchase.objects.filter(
        payment_reference=reference,
        user=request.user
    ).first()
    
    if not purchase:
        return JsonResponse({'status': 'not_found'}, status=404)
    
    return JsonResponse({
        'status': 'verified' if purchase.is_verified else 'pending',
        'vcf_id': purchase.vcf_file.id
    })

@member_required
def check_purchases(request):
    purchases = request.user.user_purchases.select_related('vcf_file').all()
    response = []
    for p in purchases:
        response.append({
            'vcf_id': p.vcf_file.id,
            'vcf_name': p.vcf_file.name,
            'reference': p.payment_reference,
            'verified': p.is_verified,
            'active': p.is_active,
            'date': p.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return JsonResponse({'purchases': response}, safe=False)
    
# =================================================================
# 3. VCF File Management Views
# =================================================================
@member_required
def VCF_Tabs(request):
    from customadmin.models import VCFFile
    joined_ids = []
    if request.user.is_authenticated:
        joined_ids = list(request.user.user_purchases.filter(is_verified=True, is_active=True).values_list('vcf_file_id', flat=True))
    vcfs = VCFFile.objects.filter(hidden=False).exclude(id__in=joined_ids).order_by('-created_at')[:5]
    return render(request, 'members/Vcf/billing.html', {'vcfs': vcfs})

@member_required
def download_vcf(request, vcf_id):
    vcf = get_object_or_404(VCFFile, id=vcf_id)
    
    # Debugging output
    print(f"Checking access for user {request.user} to VCF {vcf_id}")
    
    # For premium files, check purchase status
    if vcf.vcf_type == 'premium':
        purchase_exists = request.user.user_purchases.filter(
            vcf_file=vcf,
            is_verified=True
        ).exists()
        
        print(f"Purchase exists: {purchase_exists}")
        
        if not purchase_exists:
            print("Purchase verification failed - showing 404")
            raise Http404("You don't have access to this file")
    
    # Check if file exists
    if not vcf.file:
        return render(request, 'payment/failed.html', {
            'error': 'The requested file is not available'
        })
    
    try:
        response = FileResponse(vcf.file.open(), as_attachment=True)
        response['Content-Disposition'] = f'attachment; filename="{vcf.name}.vcf"'
        return response
    except Exception as e:
        return render(request, 'payment/failed.html', {
            'error': f'Error downloading file: {str(e)}'
        })

def subscribe_vcf(request, vcf_id):
    vcf = get_object_or_404(VCFFile, id=vcf_id, vcf_type='premium', hidden=False)
    
    # Check if user already owns this VCF
    has_access = False
    if request.user.is_authenticated:
        has_access = vcf.is_purchased_by(request.user)
        if has_access:
            messages.info(request, "You already have access to this VCF file")
    
    return render(request, 'members/subscribe_vcf.html', {
        'vcf': vcf,
        'has_access': has_access
    })

@member_required
@auth_email_required
def vcf_tabs(request):
    # Get joined free VCFs for user
    joined_free_ids = get_joined_free_vcf_ids(request.user)
    free_vcfs = VCFFile.objects.filter(vcf_type='free', hidden=False).exclude(id__in=joined_free_ids)
    premium_vcfs = VCFFile.objects.filter(vcf_type='premium', hidden=False)

    purchased_ids = []
    if request.user.is_authenticated:
        purchased_ids = list(request.user.user_purchases.filter(
            is_verified=True,
            is_active=True
        ).values_list('vcf_file_id', flat=True))
        my_premium_vcfs = VCFFile.objects.filter(
            vcf_type='premium',
            hidden=False,
            file_purchases__user=request.user,
            file_purchases__is_verified=True,
            file_purchases__is_active=True
        ).distinct()
        my_free_vcfs = VCFFile.objects.filter(
            vcf_type='free',
            hidden=False,
            file_purchases__user=request.user,
            file_purchases__is_verified=True,
            file_purchases__is_active=True
        ).distinct()
    else:
        my_premium_vcfs = VCFFile.objects.none()
        my_free_vcfs = VCFFile.objects.none()

    # Debug output
    print(f"User {request.user} purchased IDs: {purchased_ids}")

    return render(request, 'members/vcf/vcf_tabs.html', {
        'free_vcfs': free_vcfs,
        'premium_vcfs': premium_vcfs,
        'purchased_ids': purchased_ids,
        'my_premium_vcfs': my_premium_vcfs,
        'my_free_vcfs': my_free_vcfs
    })

# Authentication views
def member_register(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            logout(request)
        else:
            return redirect('members:dashboard')

    if request.method == 'POST':
        form = MemberRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            mobile = form.cleaned_data['mobile_number']
            country_code = form.cleaned_data['country_code']
            phone_number = f"{country_code}{mobile}"
            user.username = phone_number
            user.phone_number = phone_number
            user.is_staff = False
            user.save()
            login(request, user)
            messages.success(request, "Registration successful! You are now logged in.")
            return redirect('members:dashboard')
    else:
        form = MemberRegisterForm()
    
    return render(request, 'members/authentication/register.html', {'form': form})

def member_login(request):
    if request.user.is_authenticated:
        if request.user.is_staff:
            logout(request)
        else:
            # Force database query to check auth email
            user = MemberAccount.objects.get(id=request.user.id)
            if not user.authentication_email:
                messages.warning(request, "Authentication email required. Please set it in settings to continue.")
                return redirect('members:member_settings')
            return redirect('members:dashboard')

    error = None
    if request.method == 'POST':
        form = MemberLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            if user.is_staff:
                error = "Admins cannot log in here. Please use the admin portal."
            else:
                login(request, user)
                messages.success(request, "Login successful!")
                # Force check auth email after login
                if not user.authentication_email:
                    messages.warning(request, "Authentication email required. Please set it in settings to continue.")
                    return redirect('members:member_settings')
                return redirect('members:dashboard')
        else:
            error = "Invalid credentials."
    else:
        form = MemberLoginForm()

    return render(request, 'members/authentication/login.html', {
        'form': form,
        'error': error
    })

def member_logout(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('members:login')

# AJAX endpoint for password change
@csrf_exempt
@member_required
def ajax_change_password(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method.'})
    try:
        data = json.loads(request.body)
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        user = request.user

        if not old_password or not new_password:
            return JsonResponse({'success': False, 'error': 'All fields are required.'})
        if not user.check_password(old_password):
            return JsonResponse({'success': False, 'error': 'Current password is incorrect.'})
        if old_password == new_password:
            return JsonResponse({'success': False, 'error': 'New password must be different from current password.'})

        from django.core.exceptions import ValidationError
        from django.contrib.auth import password_validation
        try:
            password_validation.validate_password(new_password, user)
        except ValidationError as ve:
            return JsonResponse({'success': False, 'error': ' '.join(ve.messages)})

        user.set_password(new_password)
        user.save()

        # ✅ FORCE logout (works even if session still exists)
        logout(request)

        return JsonResponse({
            'success': True,
            'logout': True,
            'redirect_url': '/members/login/'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Unexpected error: {str(e)}'})

@member_required
def member_dashboard(request):
    # For pie chart: user premium, user free, user demo VCF counts
    user_premium_count = 0
    user_free_count = 0
    user_demo_count = 0
    if request.user.is_authenticated:
        # Premium VCFs user has subscribed to
        user_premium_count = request.user.user_purchases.filter(
            vcf_file__vcf_type='premium',
            vcf_file__hidden=False,
            is_verified=True,
            is_active=True
        ).count()
        # Free VCFs user has joined
        user_free_count = request.user.user_purchases.filter(
            vcf_file__vcf_type='free',
            vcf_file__hidden=False,
            is_verified=True,
            is_active=True
        ).count()
        # Demo VCFs user has joined (if you have a demo type)
        user_demo_count = request.user.user_purchases.filter(
            vcf_file__vcf_type='demo',
            vcf_file__hidden=False,
            is_verified=True,
            is_active=True
        ).count()
    # Total VCF files (free + premium, not hidden)
    total_vcf_files = VCFFile.objects.filter(hidden=False).count()
    # Total free packages (not hidden)
    total_free_packages = VCFFile.objects.filter(vcf_type='free', hidden=False).count()
    # Total premium VCF files subscribed/purchased by user
    total_subscribed = request.user.user_purchases.filter(
        vcf_file__vcf_type='premium',
        vcf_file__hidden=False,
        is_verified=True,
        is_active=True
    ).count() if request.user.is_authenticated else 0
    # Total contacts in all VCFs the user has joined (free and premium)
    contact_count = 0
    if request.user.is_authenticated:
        # Get all VCF ids the user has joined (free and premium)
        joined_vcf_ids = request.user.user_purchases.filter(
            is_verified=True,
            is_active=True,
            vcf_file__hidden=False
        ).values_list('vcf_file_id', flat=True)
        from customadmin.models import Contact
        contact_count = Contact.objects.filter(vcf_file_id__in=joined_vcf_ids).count()
    # Pass all to template
    return render(request, 'members/dashboard.html', {
        'total_vcf_files': total_vcf_files,
        'total_subscribed': total_subscribed,
        'total_free_packages': total_free_packages,
        'total_contacts': contact_count,
        'user_premium_count': user_premium_count,
        'user_free_count': user_free_count,
        'user_demo_count': user_demo_count,
    })




@login_required
def vcf_file_detail(request, vcf_id):
    vcf = get_object_or_404(VCFFile, id=vcf_id, vcf_type='premium', hidden=False)
    # Only allow if user has purchased/subscribed
    if not request.user.user_purchases.filter(vcf_file=vcf, is_verified=True, is_active=True).exists():
        return redirect('members:vcf_tabs')
    contacts_qs = Contact.objects.filter(vcf_file=vcf)
    # Build a list of dicts with name, phone, email for template
    contacts = []
    for c in contacts_qs:
        # Determine country code
        country_code = ''
        phone = c.phone.strip()
        if hasattr(c, 'country_code') and c.country_code:
            country_code = c.country_code
        elif phone.startswith('+') and len(phone) > 4:
            # Extract country code from phone
            country_code = phone[:4] if phone[1:4].isdigit() else phone[:3]
        elif phone and not phone.startswith('+'):
            country_code = '+234'
        # Only add country code if not already present
        display_phone = phone
        if country_code and not phone.startswith('+'):
            display_phone = country_code + phone
        contacts.append({
            'name': c.name,
            'phone': display_phone,
            'country_code': country_code,
            'email': getattr(c, 'email', '')
        })
    # Check if user is already joined as contact
    user = request.user
    profile = getattr(user, 'profile', None)
    profile_name = profile.profile_name if profile and profile.profile_name else user.get_full_name() or user.username
    number = user.mobile_number if hasattr(user, 'mobile_number') else user.username
    main_email = profile.email if profile and profile.email else user.email
    joined = any((c['phone'] == number or c['name'] == profile_name) for c in contacts)
    return render(request, 'members/vcf/vcf_file_detail.html', {
        'vcf': vcf,
        'contacts': contacts,
        'joined': joined,
        'profile_name': profile_name,
        'main_email': main_email,
        'user': user
    })

# =================================================================
# 6. Helper Functions
# =================================================================

def get_joined_free_vcf_ids(user):
    if not user.is_authenticated:
        return []
    return list(user.user_purchases.filter(
        vcf_file__vcf_type='free',
        is_verified=True,
        is_active=True
    ).values_list('vcf_file_id', flat=True))

# Join free VCF view
@member_required
def join_free_vcf(request, vcf_id):
    vcf = get_object_or_404(VCFFile, id=vcf_id, vcf_type='free', hidden=False)
    # Check if already joined
    already_joined = request.user.user_purchases.filter(vcf_file=vcf, is_verified=True, is_active=True).exists()
    if not already_joined:
        UserPurchase.objects.create(
            user=request.user,
            vcf_file=vcf,
            payment_reference=f"FREEJOIN-{request.user.id}-{vcf.id}",
            amount_paid=0,
            is_verified=True,
            is_active=True
        )
    return redirect('members:vcf_tabs')


@member_required
@require_POST
def ajax_join_vcf(request, vcf_id):
    from customadmin.models import Contact
    vcf = get_object_or_404(VCFFile, id=vcf_id)
    user = request.user
    # Get profile info
    profile = getattr(user, 'profile', None)
    profile_name = profile.profile_name if profile and profile.profile_name else user.get_full_name() or user.username
    email = profile.email if profile and profile.email else user.email
    number = user.mobile_number if hasattr(user, 'mobile_number') else user.username
    # Check if already joined (by number or name)
    already = Contact.objects.filter(vcf_file=vcf, phone=number).exists() or Contact.objects.filter(vcf_file=vcf, name=profile_name).exists()
    if already:
        return JsonResponse({'success': False, 'error': 'Already joined.'})
    # Add as contact, include email only if user wants
    contact_kwargs = {'vcf_file': vcf, 'name': profile_name, 'phone': number}
    if hasattr(profile, 'include_email_in_vcf') and profile.include_email_in_vcf:
        contact_kwargs['email'] = email
    contact = Contact.objects.create(**contact_kwargs)
    # Return new contact info for AJAX update
    return JsonResponse({'success': True, 'contact': {'name': contact.name, 'phone': contact.phone, 'email': getattr(contact, 'email', '')}})


# =================================================================
# 4. User Profile & Settings Views
# =================================================================

@login_required  # Use login_required instead of member_required to prevent redirect loops
def member_settings(request):
    # Check if user is staff and redirect if needed
    if request.user.is_staff:
        logout(request)
        messages.error(request, "Staff members must use the admin interface.")
        return redirect('customadmin:login')
        
    # Add a warning message if authentication email is not set
    if not request.user.authentication_email:
        messages.warning(request, "Please set your authentication email to continue using the platform.")
    
    password_error = None
    password_success = None
    if request.method == 'POST' and 'old_password' in request.POST:
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')
        user = request.user
        if not old_password or not new_password or not confirm_new_password:
            password_error = 'All fields are required.'
        elif new_password != confirm_new_password:
            password_error = 'New passwords do not match.'
        elif not user.check_password(old_password):
            password_error = 'Current password is incorrect.'
        elif old_password == new_password:
            password_error = 'New password must be different from current password.'
        else:
            from django.core.exceptions import ValidationError
            from django.contrib.auth import password_validation
            try:
                password_validation.validate_password(new_password, user)
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)
                password_success = 'Password updated successfully.'
            except ValidationError as ve:
                password_error = ' '.join(ve.messages)
            except Exception as e:
                password_error = f'Unexpected error: {str(e)}'
    return render(request, 'members/settings.html', {
        'password_error': password_error,
        'password_success': password_success,
    })

@member_required
@require_POST
def ajax_update_profile_name(request):
    try:
        data = json.loads(request.body)
        profile_name = data.get('profile_name', '').strip()
        if not profile_name:
            return JsonResponse({'success': False, 'error': 'Name cannot be empty.'})
        from .models import MemberProfile
        profile, _ = MemberProfile.objects.get_or_create(account=request.user)
        profile.profile_name = profile_name
        profile.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# AJAX: Update email
@member_required
@require_POST
def ajax_update_email(request):
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        if not email:
            return JsonResponse({'success': False, 'error': 'Email cannot be empty.'})
        # Update both MemberProfile and User email if needed
        from .models import MemberProfile
        profile, _ = MemberProfile.objects.get_or_create(account=request.user)
        profile.email = email
        profile.save()
        request.user.email = email
        request.user.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# AJAX: Update include_email_in_vcf
@member_required
@require_POST
def ajax_update_include_email(request):
    try:
        data = json.loads(request.body)
        include_email = data.get('include_email_in_vcf', True)
        from .models import MemberProfile
        profile, _ = MemberProfile.objects.get_or_create(account=request.user)
        profile.include_email_in_vcf = bool(include_email)
        profile.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


# AJAX: Update member info for a specific VCF file
@member_required
@require_POST
def ajax_update_vcf_member(request, vcf_id):
    try:
        data = json.loads(request.body)
        profile_name = data.get('profile_name', '').strip()
        email = data.get('email', '').strip()
        if not profile_name:
            return JsonResponse({'success': False, 'error': 'Profile name is required.'})
        from customadmin.models import Contact
        vcf = get_object_or_404(VCFFile, id=vcf_id)
        user = request.user
        # Find contact for this user in this VCF (by phone or name)
        profile = getattr(user, 'profile', None)
        number = user.mobile_number if hasattr(user, 'mobile_number') else user.username
        contact = Contact.objects.filter(vcf_file=vcf).filter(models.Q(phone=number) | models.Q(name=profile_name)).first()
        if not contact:
            return JsonResponse({'success': False, 'error': 'Contact not found for this VCF.'})
        contact.name = profile_name
        contact.email = email if email else None
        contact.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# =================================================================
# 5. Email Authentication Views
# =================================================================

@login_required
@require_http_methods(["GET", "POST"])
def auth_email(request):
    email = request.GET.get('email', '').strip()
    can_change_email = True
    days_until_next_change = 0
    email_change_interval_days = getattr(settings, 'AUTH_EMAIL_CHANGE_INTERVAL', 30)
    
    if request.user.is_authenticated:
        # Check if user has changed email recently
        if hasattr(request.user, 'auth_email_last_changed') and request.user.auth_email_last_changed:
            change_interval = timedelta(days=email_change_interval_days)
            next_change_allowed = request.user.auth_email_last_changed + change_interval
            
            if timezone.now() < next_change_allowed:
                can_change_email = False
                days_until_next_change = (next_change_allowed - timezone.now()).days
    
    return render(request, 'members/email/auth_email.html', {
        'email': email,
        'can_change_email': can_change_email,
        'email_change_interval_days': email_change_interval_days,
        'days_until_next_change': days_until_next_change
    })
    email = request.GET.get('email', '').strip()
    can_change = True
    remaining_days = 0
    
    if request.user.is_authenticated and request.user.auth_email_last_changed:
        change_interval = timedelta(days=getattr(settings, 'AUTH_EMAIL_CHANGE_INTERVAL', 30))
        next_change = request.user.auth_email_last_changed + change_interval
        
        if timezone.now() < next_change:
            can_change = False
            remaining_days = (next_change - timezone.now()).days
    
    return render(request, 'members/email/auth_email.html', {
        'email': email,
        'can_change_email': can_change,
        'remaining_days': remaining_days
    })

@require_POST
@login_required
def send_email_code(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({"error": "Email is required"}, status=400)

        # Rate limiting for code requests (60 seconds cooldown)
        cache_key = f"email_otp_sent:{request.user.id}"
        if cache.get(cache_key):
            return JsonResponse({"error": "Please wait before requesting another code"}, status=429)

        # Set cooldown
        cache.set(cache_key, True, timeout=60)

        # Create and send OTP
        EmailVerificationOTP.objects.filter(
            user=request.user,
            email=email,
            is_used=False
        ).update(is_used=True)
        
        code = str(random.randint(100000, 999999))
        otp = EmailVerificationOTP.objects.create(
            user=request.user,
            email=email,
            code=code,
            expires_at=timezone.now() + timedelta(minutes=15)
        )
        
        send_mail(
            'Your Verification Code',
            f'Your verification code is: {code}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        
        return JsonResponse({
            "ok": True, 
            "message": f"Verification code sent to {email}"
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@require_POST
@login_required
def verify_email_code(request):
    try:
        data = json.loads(request.body)
        email = data.get('email', '').lower().strip()
        code = data.get('code', '').strip()
        
        if not email or not code:
            return JsonResponse({"success": False, "error": "Email and code are required"}, status=400)
        
        otp = EmailVerificationOTP.objects.filter(
            user=request.user,
            email=email,
            code=code,
            is_used=False,
            expires_at__gt=timezone.now()
        ).order_by('-created_at').first()

        if not otp:
            return JsonResponse({"success": False, "error": "Invalid or expired code"}, status=400)

        otp.is_used = True
        otp.save()

        user = request.user
        user.authentication_email = email
        user.is_email_authenticated = True
        user.auth_email_last_changed = timezone.now()
        user.save(update_fields=['authentication_email', 'is_email_authenticated', 'auth_email_last_changed'])
        
        return JsonResponse({
            "success": True,
            "message": "Email verified and saved successfully!",
            "redirect_url": reverse('members:dashboard')
        })
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@require_POST
@login_required
def refresh_session(request):
    """Force session refresh after email update"""
    update_session_auth_hash(request, request.user)
    return JsonResponse({"status": "ok"})

def profile(request):
    def get_country_name_from_code(country_code):
        import json
        try:
            with open(os.path.join(settings.BASE_DIR, 'common/static/country-codes.json'), encoding='utf-8') as f:
                countries = json.load(f)
            for country in countries:
                if country['dial_code'] == country_code or country['code'] == country_code:
                    return country['name']
        except Exception:
            pass
        return ''

    try:
        user_profile = request.user.profile
        profile_email = user_profile.email
    except Exception:
        user_profile = None
        profile_email = None
    country_code = getattr(request.user, 'country_code', None)
    country_name = get_country_name_from_code(country_code) if country_code else ''
    context = {
        'phone_number': request.user.phone_number,
        'email': profile_email,
        'country_name': country_name,
    }
    return render(request, 'members/profile.html', context)