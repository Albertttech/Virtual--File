# common/decorators.py
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from functools import wraps
from django.shortcuts import redirect
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout

def member_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('members:login')
            
        if request.user.is_staff:
            logout(request)
            messages.error(request, "Staff members must use the admin interface.")
            return redirect('customadmin:login')

        # Force database query to get latest authentication_email status
        from members.models import MemberAccount
        user = MemberAccount.objects.filter(id=request.user.id).first()
        if not user or not user.authentication_email:
            # Only allow access to settings and logout
            allowed_paths = [
                '/members/settings/',
                '/members/logout/',
                '/members/ajax/update-auth-email/'
            ]
            if not any(request.path.startswith(path) for path in allowed_paths):
                messages.warning(request, "Authentication email required. Please set it in settings to continue.")
                return redirect('members:member_settings')
                
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def admin_required(view_func):
    @login_required(login_url=settings.ADMIN_LOGIN_URL)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_staff:
            return redirect(settings.LOGIN_REDIRECT_URL)
        return view_func(request, *args, **kwargs)
    return _wrapped_view