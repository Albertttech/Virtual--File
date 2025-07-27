from django.conf import settings
from decouple import config
import logging
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseForbidden
from .forms import VCFFileForm
from .models import VCFFile
from functools import wraps
import json
import os
logger = logging.getLogger(__name__)

# Session-based admin_required decorator (unchanged from your original)
def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.session.get('is_admin'):
            return redirect('customadmin:login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def login_view(request):
    """
    Handle admin authentication with hardcoded credentials (no database)
    """
    # If already logged in, redirect to dashboard
    if request.session.get('is_admin'):
        return redirect('customadmin:dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        ADMIN_CREDENTIALS = {
            'admin': 'admin123',
        }
        if username in ADMIN_CREDENTIALS and password == ADMIN_CREDENTIALS[username]:
            request.session['is_admin'] = True
            request.session.save()  # Explicit save
            return redirect('customadmin:dashboard')
        else:
            error = "Invalid login credentials."
    return render(request, 'customadmin/admin_login.html', {'error': error})

def logout_view(request):
    """Handle admin logout (clears session)"""
    request.session.flush()
    return redirect('customadmin:login')
    
@admin_required
def dashboard_view(request):
    """Admin dashboard view"""
    # Import MemberAccount model
    from members.models import MemberAccount
    active_users = MemberAccount.objects.count()
    total_vcf_files = VCFFile.objects.filter(hidden=False).count()
    total_subscription_vcf = VCFFile.objects.filter(vcf_type='premium', hidden=False).count()
    total_free_vcf = VCFFile.objects.filter(vcf_type='free', hidden=False).count()
    return render(request, 'customadmin/dashboard.html', {
        'active_users': active_users,
        'total_vcf_files': total_vcf_files,
        'total_subscription_vcf': total_subscription_vcf,
        'total_free_vcf': total_free_vcf,
    })

@admin_required
def all_vcf_admin(request):
    """List all VCF files with progress data"""
    vcfs = VCFFile.objects.filter(hidden=False)
    for vcf in vcfs:
        vcf.current_count = vcf.contacts.count()
        vcf.progress = int((vcf.current_count / vcf.max_contacts) * 100) if vcf.max_contacts else 0
    return render(request, 'customadmin/all_vcf.html', {'vcfs': vcfs})

@admin_required
def embed_contact_view(request):
    # Load country codes from the JSON file (like in member registration)
    country_codes_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common', 'static', 'country-codes.json')
    with open(country_codes_path, encoding='utf-8') as f:
        country_codes = json.load(f)
    vcfs = VCFFile.objects.filter(hidden=False)
    message = None
    error = None
    if request.method == 'POST':
        name = request.POST.get('contact_name', '').strip()
        country_code = request.POST.get('country_code', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        vcf_ids = request.POST.getlist('vcf_ids')
        # Validate phone: must be 9 digits
        if not name or not country_code or not phone_number or not vcf_ids:
            error = 'All fields are required and at least one VCF must be selected.'
        elif not phone_number.isdigit() or len(phone_number) != 9:
            error = 'Phone number must be exactly 9 digits.'
        else:
            full_phone = f"{country_code}{phone_number}"
            from .models import Contact
            added = 0
            for vcf_id in vcf_ids:
                try:
                    vcf = VCFFile.objects.get(id=vcf_id, hidden=False)
                    # Check for duplicate
                    if not Contact.objects.filter(vcf_file=vcf, phone=full_phone).exists():
                        Contact.objects.create(vcf_file=vcf, name=name, phone=full_phone)
                        added += 1
                except VCFFile.DoesNotExist:
                    continue
            if added:
                message = f"Contact added to {added} VCF file(s)."
            else:
                error = "Contact already exists in selected VCF(s) or VCF not found."
    return render(request, 'customadmin/embed_contact.html', {
        'country_codes': country_codes,
        'vcfs': vcfs,
        'message': message,
        'error': error,
    })
@admin_required
def hide_vcf_admin(request, vcf_id):
    """Hide or unhide a VCF file (move to/from hidden storage)"""
    try:
        vcf = VCFFile.objects.get(id=vcf_id)
        vcf.hidden = True
        vcf.save()
        logger.info(f"VCF file with id {vcf_id} hidden by admin.")
        return redirect('customadmin:all_vcf')
    except VCFFile.DoesNotExist:
        logger.error(f"VCF file with id {vcf_id} not found for hiding.")
        return HttpResponseForbidden("VCF file not found")
        
@admin_required
def vcf_vault_view(request):
    """VCF Vault page with tabs for Hidden, Demo, and Deleted VCFs"""
    hidden_vcfs = VCFFile.objects.filter(hidden=True)
    # demo_vcfs and deleted_vcfs can be implemented later
    return render(request, 'customadmin/vcf_vault.html', {
        'hidden_vcfs': hidden_vcfs,
    }) 

@admin_required
def unhide_vcf_admin(request, vcf_id):
    """Unhide a VCF file (restore from hidden storage)"""
    try:
        vcf = VCFFile.objects.get(id=vcf_id)
        vcf.hidden = False
        vcf.save()
        logger.info(f"VCF file with id {vcf_id} unhidden by admin.")
        return redirect('customadmin:all_vcf')
    except VCFFile.DoesNotExist:
        logger.error(f"VCF file with id {vcf_id} not found for unhiding.")
        return HttpResponseForbidden("VCF file not found")

@admin_required
def view_vcf_admin(request, vcf_id):
    """View details of a specific VCF file"""
    try:
        vcf = VCFFile.objects.get(id=vcf_id)
        if vcf.hidden:
            logger.warning(f"Attempt to view hidden VCF file with id {vcf_id}")
            return HttpResponseForbidden("VCF file not found")
        contacts = vcf.contacts.all()
        current_count = contacts.count()
        progress = int((current_count / vcf.max_contacts) * 100) if vcf.max_contacts else 0
        return render(request, 'customadmin/view_vcf.html', {
            'vcf': vcf,
            'contacts': contacts,
            'current_count': current_count,
            'progress': progress,
        })
    except VCFFile.DoesNotExist:
        logger.error(f"VCF file with id {vcf_id} not found")
        return HttpResponseForbidden("VCF file not found")

@admin_required
def create_vcf_admin(request):
    """Handle VCF file creation"""
    if request.method == 'POST':
        vcf_type = request.POST.get('vcf_type')
        name = request.POST.get('name')
        # For free tab
        max_contacts = request.POST.get('max_contacts')
        # For subscription tab
        contact_limit_option = request.POST.get('contact_limit_option')
        unlimited_contacts = (contact_limit_option == 'unlimited')
        subscription_price = request.POST.get('subscription_price')

        # Uniqueness check
        if VCFFile.objects.filter(name=name).exists():
            form = VCFFileForm()
            return render(request, 'customadmin/create_vcf.html', {
                'form': form,
                'error': 'A VCF file with this name already exists.'
            })

        if vcf_type == 'free':
            vcf = VCFFile.objects.create(
                name=name,
                vcf_type='free',
                max_contacts=max_contacts or None,
                unlimited_contacts=False,
                subscription_price=None
            )
        elif vcf_type == 'premium':
            vcf = VCFFile.objects.create(
                name=name,
                vcf_type='premium',
                max_contacts=(None if unlimited_contacts else max_contacts or None),
                unlimited_contacts=unlimited_contacts,
                subscription_price=subscription_price or None
            )
        logger.info(f"New {vcf_type} VCF file created successfully: {name}")
        return redirect('customadmin:dashboard')
    form = VCFFileForm()
    return render(request, 'customadmin/create_vcf.html', {'form': form})