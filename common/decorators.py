# common/decorators.py
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from functools import wraps
from django.shortcuts import redirect
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout

# Temporarily disable authentication email check
def member_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('members:login')
            
        if request.user.is_staff:
            logout(request)
            messages.error(request, "Staff members must use the admin interface.")
            return redirect('customadmin:login')

        # Skipping authentication email check for now
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