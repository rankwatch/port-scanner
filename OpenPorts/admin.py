# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from OpenPorts import models

# Register your models here.

admin.site.register(models.Scan)
admin.site.register(models.Host)
admin.site.register(models.SecuredPort)
admin.site.register(models.UnsecuredPort)
admin.site.register(models.settings)
