# vcfproject/urls.py
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse  # Add this import

def test_api(request):
    return JsonResponse({'message': 'Hello from Django!'})

urlpatterns = [
    path('api/test/', test_api),  # Test API endpoint
    path('', include('members.urls')),
    path('admin/', include('customadmin.urls')),
    path('django-admin/', admin.site.urls),
]