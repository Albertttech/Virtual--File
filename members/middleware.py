# members/middleware.py
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.contrib import messages

"""
def auth_email_required(view_func):
 
    Decorator that checks if the user has set their authentication email.
    If not, redirect to settings page with a flash message.
 
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(reverse('members:login'))
        
        if not request.user.authentication_email:
            # List of URLs that should still be accessible
            allowed_urls = [
                reverse('members:member_settings'),
                reverse('members:logout'),
                reverse('members:auth_email'),
                reverse('members:send_email_code'),
                reverse('members:verify_email_code'),
                reverse('members:login'),
                reverse('members:forgot_password'),
                reverse('members:reset_password'),
            ]
            
            if request.path not in allowed_urls:
                # Add a message with a special 'auto-dismiss' tag
                messages.warning(
                    request, 
                    "Please set your authentication email to access this page",
                    extra_tags='auto-dismiss'
                )
                return redirect(reverse('members:member_settings'))
        
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


class AuthEmailMiddleware:
    Middleware to enforce authentication email check for members.
    
    def __init__(self, get_response):
        self.get_response = get_response
        # List of URL names that should be exempt from the auth email check
        self.exempt_url_names = [
            'member_settings',  # Make sure this matches your URL name
            'auth_email',
            'send_email_code',
            'verify_email_code',
            'login',
            'logout',
            'forgot_password',
            'reset_password',
            # Add any other URLs that should be accessible without auth email
        ]

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip check for anonymous users or staff
        if not request.user.is_authenticated or request.user.is_staff:
            return None

        # Get the current URL name
        try:
            current_url_name = resolve(request.path_info).url_name
        except:
            return None

        # Check if current URL is in exempt list
        if current_url_name in self.exempt_url_names:
            return None

        # Check if authentication email is set
        if not hasattr(request.user, 'authentication_email') or not request.user.authentication_email:
            messages.warning(request, "Please set your authentication email to continue")
            return redirect(reverse('member_settings'))  # Make sure this matches your URL name

        return None"""