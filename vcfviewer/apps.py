# vcfviewer/apps.py
from django.apps import AppConfig

class VcfviewerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vcfviewer'

    def ready(self):
        import vcfviewer.signals  # noqa
