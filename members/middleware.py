from django.shortcuts import redirect
from django.urls import reverse

class MembersAuthEmailMiddleware:
    """
    Middleware to enforce authentication email check for members app pages.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the request is for the members app
        if request.path.startswith(reverse('members:dashboard')) or 'members' in request.path or request.path.startswith(reverse('members:vcf_tabs')):
            # Allow access to login and logout pages
            allowed_paths = [
                reverse('members:login'),
                reverse('members:logout'),
                reverse('members:member_settings'),
                reverse('members:update_auth_email'),  # Exclude update_auth_email page from redirect
            ]
            if request.path not in allowed_paths:
                # Check if the user is authenticated and has an authentication email
                if request.user.is_authenticated:
                    if not request.user.authentication_email:
                        # Redirect to settings page if authentication email is empty
                        return redirect(reverse('members:member_settings'))

        # Proceed with the request
        response = self.get_response(request)
        return response
