from django.urls import path

from . import views
from . import views_contact_growth
from .views import MemberPasswordResetView, forgot_password, reset_password
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView

app_name = 'members'

urlpatterns = [
    # -------------------------
    # Authentication & User Management
    # -------------------------
    path('', views.member_login),  # Redirect root to login
    path('login/', views.member_login, name='login'),
    path('logout/', views.member_logout, name='logout'),
    path('register/', views.member_register, name='register'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/', reset_password, name='reset_password'),
    path('password-reset/', MemberPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', PasswordResetDoneView.as_view(template_name='members/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(template_name='members/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset/complete/', PasswordResetCompleteView.as_view(template_name='members/password_reset_complete.html'), name='password_reset_complete'),

    # -------------------------
    # Profile & Settings
    # -------------------------
    path('profile/', views.profile, name='profile'),
    path('settings/', views.member_settings, name='member_settings'),
    path('ajax/update-profile/', views.ajax_update_profile, name='ajax_update_profile'),
    path('ajax/update-profile-name/', views.ajax_update_profile_name, name='ajax_update_profile_name'),
    path('ajax/update-email/', views.ajax_update_email, name='ajax_update_email'),
    path('ajax/update-include-email/', views.ajax_update_include_email, name='ajax_update_include_email'),
    path('ajax/change-password/', views.ajax_change_password, name='ajax_change_password'),

    # -------------------------
    # Email Verification
    # -------------------------
    path('auth_email/', views.auth_email, name='auth_email'),
    path('send_email_code/', views.send_email_code, name='send_email_code'),  # send_email_code Changed from send-email-code/
    path('verify_email_code/', views.verify_email_code, name='verify_email_code'),

    # -------------------------
    # Dashboard & Management
    # -------------------------
    path('dashboard/', views.member_dashboard, name='dashboard'),
    path('MGM/', views.vcf_management, name='vcf_management'),

    # -------------------------
    # VCF Operations
    # -------------------------
    path('VCFs/', views.VCF_Tabs, name='VCF_Tabs'),
    #path('vcf-tabs/', views.vcf_tabs, name='vcf_tabs'),
    path('vcf-table/', views.vcf_table, name='vcf_table'),
    path('vcf-detail/<int:vcf_id>/', views.vcf_file_detail, name='vcf_file_detail'),
    path('download-vcf/<int:vcf_id>/', views.download_vcf, name='download-vcf'),
    path('ajax/join-vcf/<int:vcf_id>/', views.ajax_join_vcf, name='ajax_join_vcf'),
    path('ajax/update-vcf-member/<int:vcf_id>/', views.ajax_update_vcf_member, name='ajax_update_vcf_member'),
    path('join-free-vcf/<int:vcf_id>/', views.join_free_vcf, name='join_free_vcf'),
    path('check-access/<int:vcf_id>/', views.check_vcf_access, name='check-access'),

    # -------------------------
    # Payments
    # -------------------------
    path('subscribe-vcf/<int:vcf_id>/', views.subscribe_vcf, name='subscribe_vcf'),
    path('subscribe-vcf/<int:vcf_id>/pay/', views.initiate_payment, name='initiate-payment'),
    path('verify-payment/<str:reference>/', views.verify_payment, name='verify-payment'),
    path('payment-complete/', views.payment_complete, name='payment-complete'),
    path('test-payment/<int:vcf_id>/', views.test_payment, name='test-payment'),
    path('initiate-payment/<int:vcf_id>/', views.initiate_payment, name='initiate_payment'),
    path('webhook/paystack/', views.paystack_webhook, name='paystack_webhook'),

    # -------------------------
    # Data & Analytics
    # -------------------------
    path('contact-growth-data/', views_contact_growth.contact_growth_data, name='contact_growth_data'),
]
