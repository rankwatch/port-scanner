from PortScanner.celery import app
from celery.signals import worker_process_init

from .models import Host, SecuredPort, OpenPort
from .models import SecurePortResult, OpenPortResult
from .models import Settings

from multiprocessing import current_process
from random import randint
from datetime import datetime

from py_port_scan import MultiScan

from django.shortcuts import render
from django.contrib.auth.models import User

import jsonpickle as jp


@app.task
def scanOpenPorts(username):

    last_host = Host.objects.filter(
        added_by=User.objects.get(username=username)).last()
    last_open_ports = OpenPort.objects.filter(
        added_by=User.objects.get(username=username)).last()
    last_secured_ports = SecuredPort.objects.filter(
        added_by=User.objects.get(username=username)).last()
    last_settings = Settings.objects.filter(
        user=User.objects.get(username=username)).last()

    secure_proxy = last_host.secure_proxy_ip.split(":")[0]
    secure_port = int(last_host.secure_proxy_ip.split(":")[1])
    unsecure_proxy = last_host.unsecure_proxy_ip.split(":")[0]
    unsecure_port = int(last_host.unsecure_proxy_ip.split(":")[1])
    ports = [int(x.strip()) for x in last_open_ports.unsecured_ports.split(",")]

    mulScan = MultiScan(targets=[last_host.ip],
                        ports=ports,
                        threads=last_settings.threads,
                        timeout=last_settings.timeout,
                        proxy_ip=[secure_proxy, unsecure_proxy],
                        proxy_port=[secure_port, unsecure_port])

    secure_res = dict(mulScan.run_proxy_scan(True))
    unsecure_res = dict(mulScan.run_proxy_scan(False))

    secure_scan_res = SecurePortResult(
        added_by=User.objects.get(username=username),
        host=Host.objects.get(host_id=last_host.host_id),
        open_ports=", ".join(secure_res[secure_proxy+"::"+last_host.ip]["Opened Ports"]),
        closed_ports=", ".join(secure_res[secure_proxy+"::"+last_host.ip]["Closed Ports"]),
        runtime=secure_res[secure_proxy+"::"+last_host.ip]["Runtime"])

    secure_scan_res.save()


@app.task
def addHostToDB(username, hostip, hostname, provider,
                secure_ports, open_ports,
                secure_proxy, unsecure_proxy):

    user = User.objects.get(username=username)
    host = Host(ip=hostip, added_by=user, secure_proxy_ip=secure_proxy,
                unsecure_proxy_ip=unsecure_proxy, added_on=datetime.now(),
                modified_on=datetime.now(), host_name=hostname,
                provider=provider)

    host.save()

    host_primary_key = Host.objects.filter(
        ip=hostip,
        added_by=User.objects.get(username=username)).last().host_id

    sp = SecuredPort(added_by=user,
                     host=Host.objects.get(host_id=host_primary_key),
                     secured_ports=", ".join(secure_ports.split("::")[1:-1]))

    up = OpenPort(added_by=user,
                  host=Host.objects.get(host_id=host_primary_key),
                  unsecured_ports=", ".join(open_ports.split("::")[1:-1]))

    sp.save()
    up.save()

    scanOpenPorts(username)
