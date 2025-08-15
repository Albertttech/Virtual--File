from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.

def blog(request):
    """Public blog page"""
    return render(request, 'public/pages/blog.html')

def home(request):
    """Public home page"""
    return render(request, 'public/pages/home.html')

def about_us(request):
    """About Us page view"""
    return render(request, 'public/pages/about_us.html')

def license(request):
    """License page view"""
    return render(request, 'public/pages/license.html')

def albtech(request):
    """AlbTech page view"""
    return render(request, 'public/pages/albtech.html')

def contact(request):
    """Public contact page"""  
    return render(request, 'public/pages/contact.html')
