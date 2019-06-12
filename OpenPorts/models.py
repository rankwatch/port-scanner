# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from datetime import datetime

from django.contrib.auth.models import User


class Scan(models.Model):
    scan_id = models.DateTimeField(default=datetime.now, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    data = models.CharField(max_length=260000)

    def publish(self):
        self.save()

    def __str__(self):
        return self.user_id


class Host(models.Model):
    host_id = models.IntegerField(primary_key=True)

    host_name = models.CharField(max_length=255)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)

    ip = models.GenericIPAddressField()

    added_on = models.DateTimeField(default=datetime.now, blank=True)
    modified_on = models.DateField(blank=True)

    secure_proxy_ip = models.GenericIPAddressField()
    unsecure_proxy_ip = models.GenericIPAddressField()

    provider = models.CharField(max_length=255)

    # TODO: Use IPAddress Field and make it unique
    # TODO: Added On, Modified On
    # TODO: Add host name
    # TODO: Add Provider text feild
    # TODO: Primary key

    def publish(self):
        self.save()

    def __str__(self):
        return str(self.ip)


class SecuredPort(models.Model):
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    host = models.ForeignKey(Host, on_delete=models.CASCADE)

    secured_ports = models.CharField(max_length=260000)

    def publish(self):
        self.save()

    def __str__(self):
        return self.added_by.username


class UnsecuredPort(models.Model):
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    host = models.ForeignKey(Host, on_delete=models.CASCADE)

    unsecured_ports = models.CharField(max_length=260000)

    def publish(self):
        self.save()

    def __str__(self):
        return self.added_by.username

class settings(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    secure_proxy_ip = models.GenericIPAddressField()
    unsecure_proxy_ip = models.GenericIPAddressField()
    secure_proxy_port = models.IntegerField()
    unsecure_proxy_port = models.IntegerField()

    def publish(self):
        self.save()
    
    def __str__(self):
        return str(self.user.username)
