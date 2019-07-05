# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from datetime import datetime

from django.contrib.auth.models import User


class Host(models.Model):
    host_id = models.IntegerField(primary_key=True)

    host_name = models.CharField(max_length=255)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)

    ip = models.GenericIPAddressField()

    added_on = models.DateTimeField(default=datetime.now, blank=True)
    modified_on = models.DateField(blank=True)

    secure_proxy_ip = models.CharField(max_length=21)
    unsecure_proxy_ip = models.CharField(max_length=21)

    provider = models.CharField(max_length=255)

    full_scan_flag = models.BooleanField(default=False)

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


class OpenPort(models.Model):
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    host = models.ForeignKey(Host, on_delete=models.CASCADE)

    unsecured_ports = models.CharField(max_length=260000)

    def publish(self):
        self.save()

    def __str__(self):
        return self.added_by.username


class Settings(models.Model):
    setting_id = models.IntegerField(primary_key=True)

    secure_proxy_ip = models.GenericIPAddressField()
    unsecure_proxy_ip = models.GenericIPAddressField()

    secure_proxy_port = models.IntegerField()
    unsecure_proxy_port = models.IntegerField()

    threads = models.IntegerField(default=100, blank=True)
    timeout = models.IntegerField(default=1, blank=True)

    schedule = models.CharField(max_length=255, blank=True)
    delete_scans_period = models.IntegerField(blank=True)

    def publish(self):
        self.save()

    def __str__(self):
        return "CONFIG-" + str(self.setting_id)


class SecurePortResult(models.Model):
    res_id = models.IntegerField(primary_key=True)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    host = models.ForeignKey(Host, on_delete=models.CASCADE)

    secure_open_ports = models.CharField(max_length=330000)
    secure_closed_ports = models.CharField(max_length=330000)

    unsecure_open_ports = models.CharField(max_length=330000)
    unsecure_closed_ports = models.CharField(max_length=330000)

    scanned_on = models.DateTimeField(default=datetime.now, blank=True)

    secure_scan_runtime = models.CharField(max_length=255)
    unsecure_scan_runtime = models.CharField(max_length=255)

    def publish(self):
        self.save()

    def __str__(self):
        return str(self.scanned_on) + " by " + str(self.added_by.username)


class OpenPortResult(models.Model):
    res_id = models.IntegerField(primary_key=True)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    host = models.ForeignKey(Host, on_delete=models.CASCADE)

    open_ports = models.CharField(max_length=330000)
    closed_ports = models.CharField(max_length=330000)

    scanned_on = models.DateTimeField(default=datetime.now, blank=True)

    runtime = models.CharField(max_length=255)

    def publish(self):
        self.save()

    def __str__(self):
        return str(self.scanned_on) + " by " + str(self.added_by.username)


class ScanStatus(models.Model):
    status_id = models.IntegerField(primary_key=True)
    secure_scan_status = models.BooleanField(default=False, blank=True)
    open_scan_status = models.BooleanField(default=False, blank=True)

    secure_scan_started_on = models.DateTimeField(default=datetime.now,
                                                  blank=True)
    open_scan_started_on = models.DateTimeField(default=datetime.now,
                                                blank=True)

    def publish(self):
        self.save()

    def __str__(self):
        return str(self.status_id)


class FullScanStatus(models.Model):
    status_id = models.IntegerField(primary_key=True)
    scan_status = models.BooleanField(default=False, blank=True)
    started_on = models.DateTimeField(
        default=datetime.now,
        blank=True
    )

    host = models.ForeignKey(Host, on_delete=models.CASCADE)

    def publish(self):
        self.save()

    def __str__(self):
        return str(self.status_id)


class FullScanResult(models.Model):
    scan_id = models.IntegerField(primary_key=True)

    host = models.ForeignKey(Host, on_delete=models.CASCADE)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)

    open_ports = models.TextField()
    close_ports = models.TextField()
    started_on = models.DateTimeField(
        default=datetime.now,
        blank=True
    )
    runtime = models.CharField(max_length=255)

    def publish(self):
        self.save()

    def __str__(self):
        return "Scan - " + str(self.scan_id)
