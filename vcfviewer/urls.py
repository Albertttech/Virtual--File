# vcfviewer/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('upload_vcf/', views.upload_vcf, name='upload_vcf'),
    path('save/', views.save_vcf, name='save_vcf'),
    path('', views.home, name='home'),
    path('create/', views.create_vcf, name='create_vcf'),
    path('vcf/<int:pk>/', views.view_vcf, name='view_vcf'),
]
