# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from OpenPorts import models
# Register your models here.

admin.site.register(models.Settings)
admin.site.register(models.Host)
admin.site.register(models.SecuredPort)
admin.site.register(models.OpenPort)
admin.site.register(models.SecurePortResult)
admin.site.register(models.OpenPortResult)
admin.site.register(models.ScanStatus)
