from PortScanner.celery import app
from celery.signals import worker_process_init

from .models import Scan, Host, SecuredPort, UnsecuredPort

from multiprocessing import current_process
from random import randint
from datetime import datetime

from py_port_scan import MultiScan

from django.shortcuts import render
from django.contrib.auth.models import User
from .models import settings

import jsonpickle as jp


@app.task
def scanOpenPorts(ips, ports, threads, timeout, username, password):

    res = {}

    mulScan = MultiScan(targets=ips, ports=range(ports[0], ports[1]),
                        threads=threads, timeout=timeout)

    res["ips"] = dict(mulScan.run_full_scan())
    res["total_runtime"] = round(mulScan.get_total_runtime(), 2)
    res["id"] = "".join([chr(randint(65, 65+25)) for x in range(20)])
    res["ports"] = str((ports[1] - ports[0])*len(ips))

    user_id = User.objects.get(username=username)

    scan = Scan(user_id=user_id, data=str(res))
    scan.save()


@app.task
def addHostToDB(username, hostip, secure_ports, open_ports, secure_proxy, unsecure_proxy) :
    user = User.objects.get(username=username)
    host = Host(ip=hostip, added_by=user, secure_proxy_ip=secure_proxy,
                unsecure_proxy_ip=unsecure_proxy, added_on=datetime.now(),
                modified_on=datetime.now())
    host.save()

    sp = SecuredPort(added_by=user, host=Host.objects.get(ip=hostip),
                     secured_ports=", ".join(secure_ports.split("::")[1:-1]))
    up = UnsecuredPort(added_by=user, host=Host.objects.get(ip=hostip),
                       unsecured_ports=", ".join(open_ports.split("::")[1:-1]))

    sp.save()
    up.save()
