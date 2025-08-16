# vcfproject/middleware.py
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.contrib import messages
from django.conf import settings
# dev/prod
from django.http import HttpResponseRedirect
from django.conf import settings


class AuthMiddleware:
    """
    Consolidated authentication middleware that handles both admin and member auth
    including the auth email requirement
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_url_names = [
            'login',
            'logout',
            'register',
            'forgot_password',
            'reset_password',
            'member_settings',  # Allow access to settings to set auth email
            'auth_email',
            'send_email_code',
            'verify_email_code',
            'payment-complete',  # Allow payment completion without auth check
            'verify-payment',    # Allow payment verification without auth check
            'payment_success',   # Allow payment success page without auth check
            'paystack_webhook',  # Allow webhook access
        ]
        self.admin_exempt_urls = [
            'login',
            'logout',
        ]

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip static files
        if request.path.startswith('/static/'):
            return None
            
        # Skip payment-related paths
        if any(path in request.path for path in ['/payment-complete/', '/verify-payment/', '/payment-success/', '/webhook/']):
            return None

        try:
            current_url_name = resolve(request.path_info).url_name
        except:
            return None

        # Admin path checks
        if request.path.startswith('/admin/'):
            # Check for session-based admin auth instead of Django user auth
            if not request.session.get('is_admin'):
                if current_url_name not in self.admin_exempt_urls:
                    return redirect(settings.ADMIN_LOGIN_URL)
            return None

        # Member path checks
        if request.path.startswith('/members/'):
            # Allow access to exempt URLs
            if current_url_name in self.exempt_url_names:
                return None
                
            # Check authentication
            if not request.user.is_authenticated:
                return redirect(settings.LOGIN_URL)
                
            # Check auth email for non-exempt URLs
            if (not request.user.is_staff and 
                hasattr(request.user, 'authentication_email') and 
                not request.user.authentication_email):
                messages.warning(request, "Please set your authentication email to continue")
                return redirect('members:member_settings')

        return None



class DevelopmentSSLRedirectMiddleware:
    """
    Redirects HTTPS to HTTP in development mode to prevent HTTPS errors
    with the Django development server.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only redirect in development mode
        if settings.DEPLOYMENT_MODE == 'development' and request.META.get('HTTP_X_FORWARDED_PROTO') == 'https':
            # Build HTTP URL
            http_url = request.build_absolute_uri().replace('https://', 'http://')
            return HttpResponseRedirect(http_url)
        
        return self.get_response(request)