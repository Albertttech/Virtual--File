# vcfproject/urls.py
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse  
from members import views as member_views


def test_api(request):
    return JsonResponse({'message': 'Hello from Django!'})

urlpatterns = [
    path('api/test/', test_api),  # Test API endpoint
    path('', include('public.urls')),  # Public pages (home, blog, about, contact)
    path('members/', include('members.urls')),  # Member-specific pages
    path('admin/', include('customadmin.urls')),
    path('django-admin/', admin.site.urls),
    path('payment-complete/', member_views.payment_complete, name='payment_complete'),
]
