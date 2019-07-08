from __future__ import absolute_import
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings
# from OpenPorts.models import Settings

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PortScanner.settings')
app = Celery('PortScanner')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
app.conf.beat_schedule = {
    'Scan_All_Hosts': {
        'task': 'OpenPorts.tasks.scanAllHosts',
        'schedule': crontab(
            minute="*/60"
        )
    },
    'Full_Scan_All_Hosts': {
        'task': 'OpenPorts.tasks.fullScanAllHosts',
        'schedule': crontab(
            hour=0,
            minute=0,
            day_of_week="*"
        )
    },
    'Delete_Scans': {
        'task': 'OpenPorts.tasks.deleteOldScans',
        'schedule': crontab(
            hour="*",
            minute="*/10",
            day_of_week="*"
        )
    }
}
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
