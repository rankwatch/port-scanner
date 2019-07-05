from PortScanner.celery import app
from celery.signals import worker_process_init

from .models import *

from multiprocessing import current_process
from random import randint
from datetime import datetime

from py_port_scan import MultiScan

from django.shortcuts import render
from django.contrib.auth.models import User

import jsonpickle as jp
import ast
import pytz


@app.task
def scanLastHost(username, host_id=0):
    ScanStatus().save()

    if host_id is 0:
        last_host = Host.objects.filter(
            added_by=User.objects.get(username=username)).last()
        last_open_ports = OpenPort.objects.filter(
            added_by=User.objects.get(username=username)).last()
        last_secured_ports = SecuredPort.objects.filter(
            added_by=User.objects.get(username=username)).last()
    else:
        last_host = Host.objects.filter(host_id=host_id,
                                        added_by=User.objects.get(username=username)).last()
        last_open_ports = OpenPort.objects.filter(host=Host.objects.get(host_id=host_id),
                                                  added_by=User.objects.get(username=username)).last()
        last_secured_ports = SecuredPort.objects.filter(host=Host.objects.get(host_id=host_id),
                                                        added_by=User.objects.get(username=username)).last()

    last_settings = Settings.objects.filter().last()

    secure_proxy = last_host.secure_proxy_ip.split(":")[0]
    secure_port = int(last_host.secure_proxy_ip.split(":")[1])
    unsecure_proxy = last_host.unsecure_proxy_ip.split(":")[0]
    unsecure_port = int(last_host.unsecure_proxy_ip.split(":")[1])

    if len(last_open_ports.unsecured_ports) > 0:
        open_ports = [int(x.strip())
                      for x in last_open_ports.unsecured_ports.split(",")]
    else:
        open_ports = []

    mulScan_unsecuredPorts = MultiScan(
        targets=[last_host.ip],
        ports=open_ports,
        threads=last_settings.threads,
        timeout=last_settings.timeout,
        proxy_ip=[secure_proxy, unsecure_proxy],
        proxy_port=[secure_port, unsecure_port]
    )

    stat = ScanStatus.objects.filter().last()
    open_port_res = dict(mulScan_unsecuredPorts.run_proxy_scan(False))
    open_res_write = OpenPortResult(
        added_by=User.objects.get(username=username),
        host=Host.objects.get(host_id=last_host.host_id),
        open_ports=", ".join(
            [str(x) for x in open_port_res[unsecure_proxy+"::"+last_host.ip]["Opened Ports"]]),
        closed_ports=", ".join(
            [str(x) for x in open_port_res[unsecure_proxy+"::"+last_host.ip]["Closed Ports"]]),
        runtime=open_port_res[unsecure_proxy+"::"+last_host.ip]["Runtime"],
        scanned_on=datetime.now()
    )

    open_res_write.save()

    ScanStatus.objects.update_or_create(
        status_id=stat.status_id,
        defaults={
            'open_scan_status': True
        })

    if len(last_secured_ports.secured_ports) > 0:
        secured_ports = [int(x.strip())
                         for x in last_secured_ports.secured_ports.split(",")]
    else:
        secured_ports = []

    mulScan_securedPorts = MultiScan(targets=[last_host.ip],
                                     ports=secured_ports,
                                     threads=last_settings.threads,
                                     timeout=last_settings.timeout,
                                     proxy_ip=[secure_proxy, unsecure_proxy],
                                     proxy_port=[secure_port, unsecure_port])

    secure_port_res = dict(mulScan_securedPorts.run_proxy_scan(True))
    unsecure_port_res = dict(mulScan_securedPorts.run_proxy_scan(False))

    secure_res_write = SecurePortResult(
        added_by=User.objects.get(username=username),
        scanned_on=datetime.now(),
        host=Host.objects.get(host_id=last_host.host_id),
        secure_open_ports=", ".join(
            [str(x) for x in secure_port_res[secure_proxy+"::"+last_host.ip]["Opened Ports"]]),
        secure_closed_ports=", ".join(
            [str(x) for x in secure_port_res[secure_proxy+"::"+last_host.ip]["Closed Ports"]]),
        secure_scan_runtime=secure_port_res[secure_proxy +
                                            "::"+last_host.ip]["Runtime"],
        unsecure_open_ports=", ".join(
            [str(x) for x in unsecure_port_res[unsecure_proxy+"::"+last_host.ip]["Opened Ports"]]),
        unsecure_closed_ports=", ".join(
            [str(x) for x in unsecure_port_res[unsecure_proxy+"::"+last_host.ip]["Closed Ports"]]),
        unsecure_scan_runtime=unsecure_port_res[unsecure_proxy +
                                                "::"+last_host.ip]["Runtime"]
    )

    secure_res_write.save()

    ScanStatus.objects.update_or_create(
        status_id=stat.status_id,
        defaults={
            'secure_scan_status': True
        }
    )


@app.task
def fullScanLastHost(username, host_id):
    FullScanStatus(
        host=Host.objects.get(host_id=host_id)
    ).save()

    last_host = Host.objects.filter(
        host_id=host_id,
        added_by=User.objects.get(username=username)
    ).last()

    last_open_ports = OpenPort.objects.filter(
        host=Host.objects.get(host_id=host_id),
        added_by=User.objects.get(username=username)
    ).last()

    last_secured_ports = SecuredPort.objects.filter(
        host=Host.objects.get(host_id=host_id),
        added_by=User.objects.get(username=username)
    ).last()

    last_settings = Settings.objects.filter().last()

    fullScan = MultiScan(
        targets=[last_host.ip],
        ports=range(65536),
        threads=last_settings.threads,
        timeout=last_settings.timeout
    )

    stat = FullScanStatus.objects.filter().last()
    full_scan_res = dict(fullScan.run_full_scan())

    full_scan_res_write = FullScanResult(
        added_by=User.objects.get(username=username),
        host=Host.objects.get(host_id=host_id),
        open_ports=', '.join(
            [str(x) for x in full_scan_res[last_host.ip]['Opened Ports']]
        ),
        close_ports=', '.join(
            [str(x) for x in full_scan_res[last_host.ip]['Closed Ports']]
        ),
        runtime=full_scan_res[last_host.ip]['Runtime']
    )

    full_scan_res_write.save()

    FullScanStatus.objects.update_or_create(
        status_id=stat.status_id,
        defaults={
            'scan_status': True
        }
    )


@app.task
def addHostToDB(
    username,
    hostip,
    hostname,
    provider,
    secure_ports,
    open_ports,
    full_scan_flag,
    secure_proxy,
    unsecure_proxy
):

    user = User.objects.get(username=username)
    host = Host(
        ip=hostip, added_by=user, secure_proxy_ip=secure_proxy,
        unsecure_proxy_ip=unsecure_proxy, added_on=datetime.now(),
        modified_on=datetime.now(), host_name=hostname,
        provider=provider,
        full_scan_flag=ast.literal_eval(full_scan_flag.title())
    )

    host.save()

    host_primary_key = Host.objects.filter(
        ip=hostip,
        added_by=User.objects.get(username=username)
    ).last().host_id

    sp = SecuredPort(
        added_by=user,
        host=Host.objects.get(host_id=host_primary_key),
        secured_ports=", ".join(secure_ports.split("::")[1:-1])
    )

    up = OpenPort(
        added_by=user,
        host=Host.objects.get(host_id=host_primary_key),
        unsecured_ports=", ".join(open_ports.split("::")[1:-1])
    )

    sp.save()
    up.save()

    scanLastHost.delay(username)
    if full_scan_flag == 'true':
        fullScanLastHost.delay(username, host_primary_key)
    else:
        pass


@app.task
def updateHostinDB(
    host_id,
    username,
    hostip,
    hostname,
    provider,
    full_scan_flag,
    secure_ports,
    open_ports,
    secure_proxy,
    unsecure_proxy
):

    obj, created = Host.objects.update_or_create(
        host_id=host_id,
        defaults={
            'host_ip': hostip,
            'host_name': hostname,
            'provider': provider,
            'full_scan_flag': ast.literal_eval(full_scan_flag.title()),
            'secure_proxy_ip': secure_proxy,
            'unsecure_proxy_ip': unsecure_proxy
        }
    )

    obj_1, created_1 = SecuredPort.objects.update_or_create(
        host=Host.objects.get(host_id=host_id),
        added_by=User.objects.get(username=username),
        defaults={
            'secured_ports': ", ".join(secure_ports.split("::")[1:-1])
        }
    )

    obj_2, created_2 = OpenPort.objects.update_or_create(
        host=Host.objects.get(host_id=host_id),
        added_by=User.objects.get(username=username),
        defaults={
            'unsecured_ports': ", ".join(open_ports.split("::")[1:-1])
        }
    )

    scanLastHost.delay(username, host_id)


@app.task
def scanSingleHost(
    user,
    last_host,
    last_open_ports,
    last_secured_ports,
    last_settings
):

    ScanStatus().save()
    user = jp.decode(user)
    last_host = jp.decode(last_host)
    last_open_ports = jp.decode(last_open_ports)
    last_secured_ports = jp.decode(last_secured_ports)
    last_settings = jp.decode(last_settings)

    secure_proxy = last_host.secure_proxy_ip.split(":")[0]
    secure_port = int(last_host.secure_proxy_ip.split(":")[1])
    unsecure_proxy = last_host.unsecure_proxy_ip.split(":")[0]
    unsecure_port = int(last_host.unsecure_proxy_ip.split(":")[1])

    if len(last_open_ports.unsecured_ports) > 0:
        open_ports = [int(x.strip())
                      for x in last_open_ports.unsecured_ports.split(",")]
    else:
        open_ports = []

    mulScan_unsecuredPorts = MultiScan(targets=[last_host.ip],
                                       ports=open_ports,
                                       threads=last_settings.threads,
                                       timeout=last_settings.timeout,
                                       proxy_ip=[secure_proxy,
                                                 unsecure_proxy],
                                       proxy_port=[secure_port, unsecure_port])

    stat = ScanStatus.objects.filter().last()

    open_port_res = dict(mulScan_unsecuredPorts.run_proxy_scan(False))
    open_res_write = OpenPortResult(
        added_by=User.objects.get(username=user.username),
        scanned_on=datetime.now(),
        host=Host.objects.get(host_id=last_host.host_id),
        open_ports=", ".join(
            [str(x) for x in open_port_res[unsecure_proxy+"::"+last_host.ip]["Opened Ports"]]),
        closed_ports=", ".join(
            [str(x) for x in open_port_res[unsecure_proxy+"::"+last_host.ip]["Closed Ports"]]),
        runtime=open_port_res[unsecure_proxy +
                              "::"+last_host.ip]["Runtime"]
    )

    open_res_write.save()

    ScanStatus.objects.update_or_create(
        status_id=stat.status_id,
        defaults={
            'open_scan_status': True
        })

    if len(last_secured_ports.secured_ports) > 0:
        secured_ports = [int(x.strip())
                         for x in last_secured_ports.secured_ports.split(",")]
    else:
        secure_port = []

    mulScan_securedPorts = MultiScan(targets=[last_host.ip],
                                     ports=secured_ports,
                                     threads=last_settings.threads,
                                     timeout=last_settings.timeout,
                                     proxy_ip=[secure_proxy,
                                               unsecure_proxy],
                                     proxy_port=[secure_port, unsecure_port])

    secure_port_res = dict(mulScan_securedPorts.run_proxy_scan(True))
    unsecure_port_res = dict(
        mulScan_securedPorts.run_proxy_scan(False))

    secure_res_write = SecurePortResult(
        added_by=User.objects.get(username=user.username),
        scanned_on=datetime.now(),
        host=Host.objects.get(host_id=last_host.host_id),
        secure_open_ports=", ".join(
            [str(x) for x in secure_port_res[secure_proxy+"::"+last_host.ip]["Opened Ports"]]),
        secure_closed_ports=", ".join(
            [str(x) for x in secure_port_res[secure_proxy+"::"+last_host.ip]["Closed Ports"]]),
        secure_scan_runtime=secure_port_res[secure_proxy +
                                            "::"+last_host.ip]["Runtime"],
        unsecure_open_ports=", ".join(
            [str(x) for x in unsecure_port_res[unsecure_proxy+"::"+last_host.ip]["Opened Ports"]]),
        unsecure_closed_ports=", ".join(
            [str(x) for x in unsecure_port_res[unsecure_proxy+"::"+last_host.ip]["Closed Ports"]]),
        unsecure_scan_runtime=unsecure_port_res[unsecure_proxy +
                                                "::"+last_host.ip]["Runtime"]
    )

    secure_res_write.save()

    ScanStatus.objects.update_or_create(
        status_id=stat.status_id,
        defaults={
            'secure_scan_status': True
        })


@app.task
def scanSingleUser(user):
    user = jp.decode(user)
    hosts = Host.objects.filter(
        added_by=User.objects.get(username=user.username))
    open_ports = OpenPort.objects.filter(
        added_by=User.objects.get(username=user.username))
    secured_ports = SecuredPort.objects.filter(
        added_by=User.objects.get(username=user.username))
    last_settings = Settings.objects.filter().last()

    for last_host, last_open_ports, last_secured_ports in zip(hosts, open_ports, secured_ports):
        scanSingleHost.delay(jp.encode(user), jp.encode(last_host), jp.encode(
            last_open_ports), jp.encode(last_secured_ports), jp.encode(last_settings))


@app.task
def fullScanSingleUser(user):
    user = jp.decode(user)
    hosts = Host.objects.filter(
        added_by=User.objects.get(username=user.username))

    for last_host in hosts:
        if last_host.full_scan_flag:
            fullScanLastHost.delay(
                user.username,
                last_host.host_id
            )


@app.task
def scanAllHosts():
    users = User.objects.filter()

    for user in users:
        scanSingleUser.delay(jp.encode(user))


@app.task
def fullScanAllHosts():
    users = User.objects.filter()

    for user in users:
        fullScanSingleUser.delay(jp.encode(user))


@app.task
def deleteOldScans():
    secure_results = SecurePortResult.objects.filter()
    open_results = OpenPortResult.objects.filter()
    scan_stats = ScanStatus.objects.filter()
    full_scan_stats = FullScanStatus.objects.filter()
    full_scan_results = FullScanResult.objects.filter()

    for secure_result in secure_results:
        if deleteScan(secure_result.scanned_on):
            secure_result.delete()

    for open_result in open_results:
        if deleteScan(open_result.scanned_on):
            open_result.delete()

    for scan_stat in scan_stats:
        if deleteScan(scan_stat.secure_scan_started_on):
            scan_stat.delete()

    for full_scan_stat in full_scan_stats:
        if deleteScan(full_scan_stat.started_on):
            full_scan_stat.delete()

    for full_scan_result in full_scan_results:
        if deleteScan(full_scan_result.started_on):
            full_scan_result.delete()


def deleteScan(scan_time):
    config = Settings.objects.filter().last()

    tz = pytz.timezone("Asia/Calcutta")
    seconds = (tz.localize(datetime.now()) - scan_time).total_seconds()

    if seconds > config.delete_scan_period:
        return True
    else:
        return False
