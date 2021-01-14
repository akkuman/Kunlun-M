import os

from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

app = Celery('CodeAudit')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# initialize environment
import django
django.setup()
from core import main

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()
# Load task modules from main app
app.autodiscover_tasks(['Kunlun_M'])
