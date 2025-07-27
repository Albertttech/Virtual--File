import os
from django.views.decorators.csrf import csrf_exempt
import uuid
import requests
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login, logout
from django.http import FileResponse, Http404, JsonResponse, HttpResponse
from django.urls import reverse
from django.db import IntegrityError
from django.contrib import messages
from .models import VCFFile, UserPurchase
from .forms import MemberRegisterForm, MemberLoginForm
from common.decorators import member_required
from customadmin.models import Contact
import hmac
import hashlib
import json
from django.views.decorators.http import require_POST
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

    return render(request, 'members/vcf_tabs.html', {
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
            user.username = f"{form.cleaned_data['country_code']}{form.cleaned_data['mobile_number']}"
            user.is_staff = False
            user.save()
            login(request, user)
            messages.success(request, "Registration successful! You are now logged in.")
            return redirect('members:dashboard')
    else:
        form = MemberRegisterForm()
    
    return render(request, 'members/register.html', {'form': form})

def member_login(request):
    if request.user.is_authenticated:
        if not request.user.is_staff:
            return redirect('members:dashboard')
        logout(request)

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
                return redirect('members:dashboard')
        else:
            error = "Invalid credentials."
    else:
        form = MemberLoginForm()

    return render(request, 'members/login.html', {
        'form': form,
        'error': error
    })

def member_logout(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('members:login')

@member_required
def member_dashboard(request):
    return render(request, 'members/dashboard.html')




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
        contacts.append({
            'name': c.name,
            'phone': c.phone,
            'email': getattr(c, 'email', '')
        })
    # Check if user is already joined as contact
    user = request.user
    profile = getattr(user, 'profile', None)
    profile_name = profile.profile_name if profile and profile.profile_name else user.get_full_name() or user.username
    number = user.mobile_number if hasattr(user, 'mobile_number') else user.username
    joined = any((c['phone'] == number or c['name'] == profile_name) for c in contacts)
    return render(request, 'members/vcf_file_detail.html', {'vcf': vcf, 'contacts': contacts, 'joined': joined})

# Helper: get joined free VCF ids for user
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
    from .models import MemberProfile
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


# Member settings page
@member_required
def member_settings(request):
    return render(request, 'members/settings.html')

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