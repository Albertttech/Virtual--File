# middleware.py
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.conf import settings
from django.contrib import messages
from members.models import MemberAccount
from django.db.models import Q

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
            reverse('members:forgot_password'),
            reverse('members:reset_password'),
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
        if request.path.startswith('/members/') and not request.user.is_authenticated:
            return redirect(settings.LOGIN_URL)
                
        return self.get_response(request)

# Temporarily disable authentication email check
# class AuthEmailMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         if request.user.is_authenticated and not request.user.is_staff:
#             # Essential paths that don't require auth email or handle it themselves
#             allowed_paths = [
#                 '/members/login/',
#                 '/members/logout/',
#                 '/members/settings/',
#                 '/members/ajax/update-auth-email/',
#                 '/members/static/',
#                 '/members/forgot-password/',
#                 '/members/reset-password/'
#             ]

#             # Ensure no redirect loop by skipping allowed paths
#             if any(request.path.startswith(path) for path in allowed_paths):
#                 return self.get_response(request)

#             # Redirect to settings if no auth email is set
#             try:
#                 user = MemberAccount.objects.get(id=request.user.id)
#                 if not user.authentication_email:
#                     messages.warning(request, "Please set your authentication email to continue.")
#                     return redirect('members:member_settings')
#             except MemberAccount.DoesNotExist:
#                 messages.error(request, "Account not found.")
#                 return redirect('members:logout')

#         return self.get_response(request)