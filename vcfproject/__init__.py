from .settings import *

# Import Celery app so that shared_task decorator works
try:
    from .celery import app as celery_app
    __all__ = ('celery_app',)
except ImportError:
    # Celery not installed, continue without it
    pass