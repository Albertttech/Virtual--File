# middleware.py
from django.shortcuts import redirect
from django.urls import reverse
from django.conf import settings

class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip middleware for static files
        if request.path.startswith('/static/'):
            return self.get_response(request)
            
        # Member paths that should be accessible without authentication
        member_paths = [
            reverse('members:login'),
            reverse('members:logout'),
            reverse('members:register'),
        ]
        
        # Admin paths that should be accessible without authentication
        admin_paths = [
            reverse('customadmin:login'),
            reverse('customadmin:logout'),
        ]
        
        # Allow access to member and admin auth paths
        if any(request.path.startswith(path) for path in member_paths + admin_paths):
            return self.get_response(request)
            
        # For admin paths (/admin/), check either session or staff status
        if request.path.startswith('/admin/'):
            if not (request.session.get('is_admin') or 
                   (request.user.is_authenticated and request.user.is_staff)):
                return redirect(settings.ADMIN_LOGIN_URL)
                
        # For member paths, ensure they're authenticated (if needed)
        # This maintains your existing member auth flow
        if request.path.startswith('/members/') and not request.user.is_authenticated:
            return redirect(settings.LOGIN_URL)
                
        return self.get_response(request)