from django.shortcuts import redirect
from django.urls import reverse

# Temporarily disable authentication email check
# class MembersAuthEmailMiddleware:
#     """
#     Middleware to enforce authentication email check for members app pages.
#     """
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         # Check if the request is for the members app
#         if request.path.startswith('/members/'):
#             # Allow access to these pages without redirect
#             allowed_paths = [
#                 reverse('members:login'),
#                 reverse('members:logout'),
#                 reverse('members:member_settings'),
#                 reverse('members:update_auth_email'),  # Exclude update_auth_email page from redirect
#             ]
            
#             # First check if this is an allowed path
#             if request.path in allowed_paths:
#                 return self.get_response(request)
#             # Then check authentication and auth email
#             if request.user.is_authenticated:
#                 if not request.user.authentication_email:
#                     # Redirect to settings page if authentication email is empty
#                     return redirect(reverse('members:member_settings'))

#         # Proceed with the request
#         response = self.get_response(request)
#         return response
