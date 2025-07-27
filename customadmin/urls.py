# customadmin/urls.py
from django.urls import path
from . import views

app_name = 'customadmin'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('view-vcf/<int:vcf_id>/', views.view_vcf_admin, name='view_vcf'),
    path('create-vcf/', views.create_vcf_admin, name='create_vcf'),
    path('all-vcf/', views.all_vcf_admin, name='all_vcf'),
    path('embed-contact/', views.embed_contact_view, name='embed_contact'),
    path('vcf/<int:vcf_id>/hide/', views.hide_vcf_admin, name='hide_vcf'),
    path('vcf/<int:vcf_id>/unhide/', views.unhide_vcf_admin, name='unhide_vcf'),
    path('vcf-vault/', views.vcf_vault_view, name='vcf_vault'),
    path('', views.dashboard_view, name='index'),  # This handles /admin/
]