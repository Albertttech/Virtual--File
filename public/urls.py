from django.urls import path
from . import views

app_name = 'public'

urlpatterns = [
    path('', views.home, name='home'),
    path('blog/', views.blog, name='blog'),
    path('about/', views.about_us, name='about_us'),  # Single URL for about page
    path('license/', views.license, name='license'),
    path('litarch/', views.albtech, name='litarch'),
    path('contact/', views.contact, name='contact'),
]
