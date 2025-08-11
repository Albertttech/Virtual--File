# vcfproject/wsgi.py
import os
import sys
from django.core.wsgi import get_wsgi_application

# Add your project directory to the Python path
project_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_path not in sys.path:
    sys.path.append(project_path)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vcfproject.settings')

try:
    application = get_wsgi_application()
    print("WSGI application loaded successfully")
except Exception as e:
    print(f"Error loading WSGI application: {e}")
    raise