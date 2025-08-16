#!/usr/bin/env python
"""
Test script to validate email verification fixes
"""
import os
import sys
import django
import json
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core.cache import cache

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vcfproject.settings')
django.setup()

from members.models import MemberAccount

def test_email_verification_endpoint():
    """Test the send_email_code endpoint with various scenarios"""
    print("Testing email verification endpoint...")
    
    client = Client(enforce_csrf_checks=True)
    
    # Create a test user
    user = User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )
    
    # Create member account
    member = MemberAccount.objects.create(
        user=user,
        email_verified=False,
        phone_verified=False
    )
    
    # Login the user
    client.login(username='testuser', password='testpass123')
    
    print("✓ Test user created and logged in")
    
    # Test 1: Request without CSRF token
    print("\n1. Testing request without CSRF token...")
    response = client.post('/members/send-email-code/', 
                          data=json.dumps({'email': 'test@example.com'}),
                          content_type='application/json')
    print(f"Response status: {response.status_code}")
    if response.status_code == 403:
        print("✓ CSRF protection working correctly")
    else:
        print("✗ CSRF protection not working as expected")
    
    # Test 2: Request with empty body
    print("\n2. Testing request with empty body...")
    response = client.post('/members/send-email-code/', 
                          data='',
                          content_type='application/json',
                          HTTP_X_CSRFTOKEN=client.session.get('csrf_token', ''))
    print(f"Response status: {response.status_code}")
    if response.status_code == 400:
        response_data = json.loads(response.content)
        print(f"✓ Empty body handled correctly: {response_data.get('error')}")
    else:
        print("✗ Empty body not handled correctly")
    
    # Test 3: Request with invalid JSON
    print("\n3. Testing request with invalid JSON...")
    csrf_token = client.get('/members/auth-email/').cookies.get('csrftoken')
    if csrf_token:
        csrf_token = csrf_token.value
    else:
        csrf_token = 'dummy_token'
    
    response = client.post('/members/send-email-code/', 
                          data='{invalid json}',
                          content_type='application/json',
                          HTTP_X_CSRFTOKEN=csrf_token)
    print(f"Response status: {response.status_code}")
    if response.status_code == 400:
        response_data = json.loads(response.content)
        print(f"✓ Invalid JSON handled correctly: {response_data.get('error')}")
    else:
        print("✗ Invalid JSON not handled correctly")
    
    # Test 4: Request without email field
    print("\n4. Testing request without email field...")
    response = client.post('/members/send-email-code/', 
                          data=json.dumps({}),
                          content_type='application/json',
                          HTTP_X_CSRFTOKEN=csrf_token)
    print(f"Response status: {response.status_code}")
    if response.status_code == 400:
        response_data = json.loads(response.content)
        print(f"✓ Missing email handled correctly: {response_data.get('error')}")
    else:
        print("✗ Missing email not handled correctly")
    
    # Test 5: Request with invalid email format
    print("\n5. Testing request with invalid email format...")
    response = client.post('/members/send-email-code/', 
                          data=json.dumps({'email': 'invalid-email'}),
                          content_type='application/json',
                          HTTP_X_CSRFTOKEN=csrf_token)
    print(f"Response status: {response.status_code}")
    if response.status_code == 400:
        response_data = json.loads(response.content)
        print(f"✓ Invalid email format handled correctly: {response_data.get('error')}")
    else:
        print("✗ Invalid email format not handled correctly")
    
    # Clean up
    cache.clear()
    user.delete()
    print("\n✓ Test completed and cleaned up")

if __name__ == '__main__':
    test_email_verification_endpoint()
