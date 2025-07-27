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
import hmac
import hashlib
import json

def get_paystack_credentials():
    """Get Paystack credentials from settings"""
    return {
        'secret_key': settings.PAYSTACK_SECRET_KEY,
        'public_key': settings.PAYSTACK_PUBLIC_KEY,
        'success_url': settings.PAYSTACK_SUCCESS_URL
    }

@member_required
def test_payment(request, vcf_id):
    if not settings.TEST_MODE:
        raise Http404("Test mode only available when TEST_MODE=True")
    
    vcf = get_object_or_404(VCFFile, id=vcf_id)
    
    purchase, created = UserPurchase.objects.get_or_create(
        user=request.user,
        vcf_file=vcf,
        defaults={
            'payment_reference': "TEST_REF_" + str(uuid.uuid4())[:8],
            'amount_paid': vcf.subscription_price,
            'is_verified': True
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
        
        secret = get_paystack_credentials()['secret_key']
        computed_signature = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha512
        ).hexdigest()
        
        if computed_signature != signature:
            return HttpResponse(status=400)
        
        event = json.loads(payload)
        
        if event['event'] == 'charge.success':
            data = event['data']
            reference = data['reference']
            return verify_payment(request, reference)
            
        return HttpResponse(status=200)
    return HttpResponse(status=405)

@member_required
def initiate_payment(request, vcf_id):
    credentials = get_paystack_credentials()
    vcf = get_object_or_404(VCFFile, id=vcf_id, vcf_type='premium', hidden=False)

    if request.method == 'POST':
        email = request.POST.get('email', f"{request.user.username}@vcfapp.com")
        amount = int(float(vcf.subscription_price) * 100)

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
                if auth_url := data.get('authorization_url'):
                    return redirect(auth_url)
                messages.error(request, "Could not retrieve payment link. Try again.")
            else:
                messages.error(request, f"Payment failed: {response.json().get('message', 'Unknown error')}")

        except requests.exceptions.RequestException as e:
            messages.error(request, f"Network error: {str(e)}")

        return render(request, 'payment/failed.html')

    return render(request, 'payment/payment_form.html', {
        'vcf': vcf,
        'public_key': credentials['public_key'],
        'amount': vcf.subscription_price
    })

@member_required
def payment_complete(request):
    if reference := request.GET.get('reference'):
        return verify_payment(request, reference)
    messages.error(request, "Missing payment reference")
    return redirect('members:vcf_tabs')

@member_required
def verify_payment(request, reference):
    User = get_user_model()
    credentials = get_paystack_credentials()

    try:
        headers = {
            'Authorization': f'Bearer {credentials["secret_key"]}',
            'Content-Type': 'application/json',
        }
        
        response = requests.get(
            f'https://api.paystack.co/transaction/verify/{reference}',
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()

        if not data.get('status'):
            messages.error(request, "Payment verification failed with Paystack")
            return redirect('members:vcf_tabs')

        tx = data['data']
        if tx['status'] != 'success':
            messages.error(request, f"Payment status: {tx['status']}")
            return redirect('members:vcf_tabs')

        metadata = tx.get('metadata', {})        
        user_id = metadata.get('user_id', request.user.id)
        vcf_id = metadata.get('vcf_file_id', request.GET.get('vcf_id'))
        
        if not vcf_id:
            messages.error(request, "Missing VCF file information in payment")
            return redirect('members:vcf_tabs')

        try:
            user = User.objects.get(id=user_id)
            vcf = VCFFile.objects.get(id=vcf_id)
        except User.DoesNotExist:
            messages.error(request, "User account not found")
            return redirect('members:vcf_tabs')
        except VCFFile.DoesNotExist:
            messages.error(request, "VCF file not found")
            return redirect('members:vcf_tabs')

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

        messages.success(request, "Payment verified successfully! You can now access the VCF file.")
        return redirect('members:vcf_tabs')

    except requests.exceptions.RequestException as e:
        messages.error(request, "Network error verifying payment. Please check your purchase history.")
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
    
    return redirect('members:vcf_tabs')

# ... [Keep all other existing view functions unchanged] ...