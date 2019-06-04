# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from datetime import datetime

# Create your models here.


class Scan(models.Model):
    scan_id = models.DateTimeField(default=datetime.now, blank=True)
    user_id = models.CharField(max_length=255)
    data = models.CharField(max_length=260000)

    def publish(self):
        self.save()

    def __str__(self):
        return self.user_id
