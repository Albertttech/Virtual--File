from django.urls import path

from . import views
from . import views_contact_growth
from .views import MemberPasswordResetView
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView

app_name = 'members'

urlpatterns = [
    path('password-reset/', MemberPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', PasswordResetDoneView.as_view(template_name='members/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(template_name='members/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset/complete/', PasswordResetCompleteView.as_view(template_name='members/password_reset_complete.html'), name='password_reset_complete'),
    path('ajax/update-include-email/', views.ajax_update_include_email, name='ajax_update_include_email'),
    path('ajax/change-password/', views.ajax_change_password, name='ajax_change_password'),
    path('settings/', views.member_settings, name='member_settings'),
    path('ajax/update-profile-name/', views.ajax_update_profile_name, name='ajax_update_profile_name'),
    path('ajax/update-email/', views.ajax_update_email, name='ajax_update_email'),
    path('test-payment/<int:vcf_id>/', views.test_payment, name='test-payment'),
    path('ajax/update-vcf-member/<int:vcf_id>/', views.ajax_update_vcf_member, name='ajax_update_vcf_member'),
    path('subscribe-vcf/<int:vcf_id>/pay/', views.initiate_payment, name='initiate-payment'),
    path('verify-payment/<str:reference>/', views.verify_payment, name='verify-payment'),
    path('download-vcf/<int:vcf_id>/', views.download_vcf, name='download-vcf'),
    path('login/', views.member_login, name='login'),
    path('logout/', views.member_logout, name='logout'),
    path('register/', views.member_register, name='register'),
    path('dashboard/', views.member_dashboard, name='dashboard'),
    path('vcf-tabs/', views.vcf_tabs, name='vcf_tabs'),
    path('vcf-detail/<int:vcf_id>/', views.vcf_file_detail, name='vcf_file_detail'),
    path('ajax/join-vcf/<int:vcf_id>/', views.ajax_join_vcf, name='ajax_join_vcf'),
    path('contact-growth-data/', views_contact_growth.contact_growth_data, name='contact_growth_data'),
    path('join-free-vcf/<int:vcf_id>/', views.join_free_vcf, name='join_free_vcf'),
    path('subscribe-vcf/<int:vcf_id>/', views.subscribe_vcf, name='subscribe_vcf'),
    path('check-access/<int:vcf_id>/', views.check_vcf_access, name='check-access'),
    path('payment-complete/', views.payment_complete, name='payment-complete'),
    path('', views.member_login),  # Redirect root to login
]