# common/decorators.py
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.contrib import messages
from functools import wraps
from django.conf import settings

def member_auth_required(view_func):
    """
    Combined decorator that handles both member and email authentication checks
    with minimal database queries
    """
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

        # Check authentication email using cached property
        if not request.user.cached_authentication_email:
            # List of allowed URL names (not paths)
            allowed_url_names = [
                'member_settings',
                'logout',
                'auth_email',
                'send_email_code',
                'verify_email_code',
                'login',
                'forgot_password',
                'reset_password',
            ]
            
            # Resolve current URL name
            try:
                current_url_name = resolve(request.path_info).url_name
            except:
                current_url_name = None
                
            if current_url_name not in allowed_url_names:
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