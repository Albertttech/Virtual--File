# common/decorators.py
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.contrib import messages
from functools import wraps
from django.conf import settings

def member_auth_required(view_func):
    """
    Optimized decorator that handles both member and email authentication checks
    with minimal database queries and efficient URL resolution
    """
    # Cache allowed URL names to avoid repeated list creation
    ALLOWED_URL_NAMES = frozenset([
        'member_settings',
        'logout', 
        'auth_email',
        'send_email_code',
        'verify_email_code',
        'login',
        'forgot_password',
        'reset_password',
    ])
    
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check authentication
        if not request.user.is_authenticated:
            return redirect('members:login')
            
        # Check if staff user
        if request.user.is_staff:
            logout(request)
            messages.error(request, "Staff members must use the admin interface.")
            return redirect(settings.ADMIN_LOGIN_URL)

        # Use resolver_match for efficient URL name access
        current_url_name = getattr(request.resolver_match, 'url_name', None) if request.resolver_match else None
        
        # Check authentication email using cached property
        if not getattr(request.user, 'authentication_email', None):
            if current_url_name not in ALLOWED_URL_NAMES:
                messages.warning(
                    request, 
                    "Please set your authentication email to access this page",
                    extra_tags='auto-dismiss'
                )
                return redirect(reverse('members:member_settings'))
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check session-based admin auth instead of Django user auth
        if not request.session.get('is_admin'):
            return redirect(settings.ADMIN_LOGIN_URL)
        return view_func(request, *args, **kwargs)
    return _wrapped_view