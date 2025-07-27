# vcfproject/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('', include('members.urls')),
    path('admin/', include('customadmin.urls')),
    path('django-admin/', admin.site.urls),
]