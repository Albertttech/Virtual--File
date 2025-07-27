from django.urls import path
from . import views

app_name = 'members'

urlpatterns = [
    path('test-payment/<int:vcf_id>/', views.test_payment, name='test-payment'),
    path('subscribe-vcf/<int:vcf_id>/pay/', views.initiate_payment, name='initiate-payment'),
    path('verify-payment/<str:reference>/', views.verify_payment, name='verify-payment'),
    path('download-vcf/<int:vcf_id>/', views.download_vcf, name='download-vcf'),
    path('login/', views.member_login, name='login'),
    path('logout/', views.member_logout, name='logout'),
    path('register/', views.member_register, name='register'),
    path('dashboard/', views.member_dashboard, name='dashboard'),
    path('vcf-tabs/', views.vcf_tabs, name='vcf_tabs'),
    path('subscribe-vcf/<int:vcf_id>/', views.subscribe_vcf, name='subscribe_vcf'),
    path('check-access/<int:vcf_id>/', views.check_vcf_access, name='check-access'),
    path('payment-complete/', views.payment_complete, name='payment-complete'),
    path('', views.member_login),  # Redirect root to login
]