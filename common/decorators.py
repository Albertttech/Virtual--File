# common/decorators.py
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from functools import wraps
from django.shortcuts import redirect
from django.conf import settings

def member_required(view_func):
    @login_required(login_url=settings.LOGIN_URL)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_staff:
            return redirect(settings.ADMIN_LOGIN_REDIRECT_URL)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def admin_required(view_func):
    @login_required(login_url=settings.ADMIN_LOGIN_URL)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_staff:
            return redirect(settings.LOGIN_REDIRECT_URL)
        return view_func(request, *args, **kwargs)
    return _wrapped_view