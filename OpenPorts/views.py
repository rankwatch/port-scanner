# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from celery.schedules import crontab
from celery import Celery

from django_celery_beat.models import CrontabSchedule
from django_celery_beat.models import PeriodicTask
from django_celery_beat.models import PeriodicTasks

from .tasks import *
from .models import *

import ast
import pytz
import time


@login_required
def home(request):
    return render(request, 'index.html')


@login_required
def index(request):

    ips = list(map(lambda x: x.strip(), list(request.GET.get('IPAddr')
                                             .split(","))))
    ports = list(map(int, request.GET.get('PortRange').split('-'))) if "-" in str(
        request.GET.get('PortRange')) else [0, int(request.GET.get('PortRange'))]
    threads = int(request.GET.get('Threads'))
    timeout = int(request.GET.get('Timeout'))

    scanOpenPorts.delay(ips, ports, threads, timeout,
                        request.user.username, request.user.password)

    return HttpResponse("<h1>Success</h1>")


@login_required
def fetch(request):
    user_id = str(request.user.username) + str(request.user.password)
    last_updated = Scan.objects.filter(user_id=user_id).last()
    res = ast.literal_eval(last_updated.data)
    return render(request, "results.html", res)


@login_required
def view_scans(request):
    res = {}
    user_id = str(request.user.username) + str(request.user.password)
    all_scans = Scan.objects.filter(user_id=user_id)

    for scan in all_scans:
        res[scan.scan_id] = ast.literal_eval(scan.data)

    return render(request, 'view_scans.html', {"scans": res})


@login_required
def addhost(request):
    return render(request, "add_host_ip.html")


@login_required
def addnewhost(request):

    s = request.GET.get('secure_proxy')
    u = request.GET.get('unsecure_proxy')
    config = Settings.objects.filter().last()

    if len(s) == 0:
        secure_proxy = str(config.secure_proxy_ip)+":" + \
            str(config.secure_proxy_port)
    else:
        secure_proxy = s

    if len(u) == 0:
        unsecure_proxy = str(config.unsecure_proxy_ip)+":" + \
            str(config.unsecure_proxy_port)
    else:
        unsecure_proxy = u

    addHostToDB.delay(request.user.username,
                      request.GET.get('host_ip'),
                      request.GET.get('hostname'),
                      request.GET.get('provider'),
                      request.GET.get('secure_ports'),
                      request.GET.get('open_ports'),
                      request.GET.get('full_scan_flag'),
                      secure_proxy,
                      unsecure_proxy)

    return HttpResponse("Success")


@login_required
def add_settings(request):
    try:
        config = Settings.objects.filter().last()

        secure_proxy = str(config.secure_proxy_ip)+":" + \
            str(config.secure_proxy_port)
        unsecure_proxy = str(config.unsecure_proxy_ip)+":" + \
            str(config.unsecure_proxy_port)
        threads = str(config.threads)
        timeout = str(config.timeout)
        scanf = str(config.schedule)
        delete_scan_period = str(config.delete_scan_period)

        return render(request, "settings.html", {
            "result": {
                "Secure": secure_proxy,
                "Unsecure": unsecure_proxy,
                "threads": threads,
                "timeout": timeout,
                "scanfrequency": scanf,
                "deleteScanPeriod": delete_scan_period
            }
        })

    except:
        return render(request, "settings.html")


@login_required
def new_settings(request):
    secure = request.GET.get('secure_proxy')
    unsecure = request.GET.get('unsecure_proxy')
    secure_ip_port = secure.split(":")
    unsecure_ip_port = unsecure.split(":")
    scanf = str(request.GET.get("scanfrequency"))
    delP = int(request.GET.get("deleteScanPeriod"))
    s = Settings(
        secure_proxy_ip=secure_ip_port[0],
        unsecure_proxy_ip=unsecure_ip_port[0],
        secure_proxy_port=secure_ip_port[1],
        unsecure_proxy_port=unsecure_ip_port[1],
        threads=request.GET.get("threads"),
        timeout=request.GET.get("timeout"),
        schedule=scanf,
        delete_scan_period=delP
    )

    s.save()

    try:
        m = scanf.split(":")[0]
        h = scanf.split(":")[1]
        d = scanf.split(":")[2]
        dM = scanf.split(":")[3]
        MY = scanf.split(":")[4]
        changePeriod(m, h, d, dM, MY)
    except:
        changePeriod()

    return HttpResponse("Success")


@login_required
def allhosts(request):

    hosts = Host.objects.filter(
        added_by=User.objects.get(
            username=request.user.username))

    res = {}

    for host in hosts:
        try:
            host_dic = {}

            secure_res = SecurePortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()
            open_res = OpenPortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()

            host_dic["ip"] = str(host.ip)

            try:
                if len(secure_res.secure_open_ports) > 0:
                    secure_open = [int(x.strip())
                                   for x in secure_res.secure_open_ports.split(",")]
                else:
                    raise Exception

            except:
                secure_open = []

            try:
                if len(secure_res.unsecure_open_ports) > 0:
                    unsecure_open = [int(x.strip())
                                     for x in secure_res.unsecure_open_ports.split(",")]
                else:
                    raise Exception
            except:
                unsecure_open = []

            host_dic["secure_ports"] = len(
                set(secure_open) - set(unsecure_open))

            try:
                if len(secure_res.unsecure_open_ports) > 0:
                    host_dic["unsecure_ports"] = len(
                        [int(x.strip())
                         for x in secure_res.unsecure_open_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                host_dic["unsecure_ports"] = 0

            try:
                if len(secure_res.secure_closed_ports) > 0:
                    secure_closed = len(
                        [int(x.strip())
                         for x in secure_res.secure_closed_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                secure_closed = 0

            try:
                if len(open_res.closed_ports) > 0:
                    open_closed = len(
                        [int(x.strip())
                         for x in open_res.closed_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                open_closed = 0

            host_dic["inaccessible"] = secure_closed + open_closed

            try:
                if len(open_res.open_ports) > 0:
                    host_dic["open_ports"] = len(
                        [int(x.strip())
                         for x in open_res.open_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                host_dic["open_ports"] = 0

            host_dic["status"] = 0 if host_dic["unsecure_ports"] > 0 else 1

            res[host.host_id] = host_dic

        except Exception as e:
            print(e)

    return render(request, "view_All_Hosts.html", {"result": res})


@login_required
def editHost(request):
    host = Host.objects.get(host_id=request.GET.get("host_id"))
    sec = SecuredPort.objects.get(host=host)
    op = OpenPort.objects.get(host=host)
    host_dic = {
        "host_id": host.host_id,
        "host_ip": host.ip,
        "host_name": host.host_name,
        "provider": host.provider,
        "full_scan_flag": host.full_scan_flag,
        "secure_proxy_ip": host.secure_proxy_ip,
        "unsecure_proxy_ip": host.unsecure_proxy_ip,
        "open_ports": [str(x.strip()) for x in op.unsecured_ports.split(",")],
        "secure_ports": [str(x.strip()) for x in sec.secured_ports.split(",")]
    }
    return render(request, "add_host_ip.html", {"result": host_dic})


@login_required
def viewReport(request):
    host = Host.objects.get(host_id=request.GET.get("host_id"))
    sec = SecuredPort.objects.get(host=host)
    op = OpenPort.objects.get(host=host)
    sec_res = SecurePortResult.objects.filter(host=host).last()
    op_res = OpenPortResult.objects.filter(host=host).last()
    if len(sec_res.secure_open_ports) > 0:
        secure = [int(x.strip()) for x in sec_res.secure_open_ports.split(",")]
    else:
        secure = []

    if len(sec_res.unsecure_open_ports) > 0:
        unsecure = [int(x.strip())
                    for x in sec_res.unsecure_open_ports.split(",")]
    else:
        unsecure = []

    if len(op_res.open_ports) > 0:
        open = [int(x.strip()) for x in op_res.open_ports.split(",")]
    else:
        open = []

    res = {}
    i = 0
    if len(sec.secured_ports) > 0:
        secure_port = [int(x.strip()) for x in sec.secured_ports.split(",")]
    else:
        secure_port = []

    if len(op.unsecured_ports) > 0:
        open_port = [int(x.strip()) for x in op.unsecured_ports.split(",")]
    else:
        open_port = []

    for port in secure_port:
        dat = {}
        if port in secure:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Secured"
        elif port in unsecure:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Unsecured"
        else:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Inaccessible"
        res[i] = dat
        i += 1
    for port in open_port:
        dat = {}
        if port in open:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Open"
        else:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Inaccessible"
        res[i] = dat
        i+=1
    csv = []
    for i in res:
        csv.append(res[i])
    return render(request, "view_report.html" , {"result" : res, "host_id":request.GET.get("host_id"), 'csv':str(csv),'host':str(host.ip)})


@login_required
def viewReports(request):
    ip = request.GET.get("ip")
    tz = pytz.timezone("Asia/Calcutta")
    res = {}
    host = Host.objects.get(ip = str(ip))
    # print("\n"*3,ip)
    try:
        all_reports = SecurePortResult.objects.filter(host = Host.objects.get(ip = str(ip)))
        i = 0
        for report in all_reports:
            dat = {}
            dat['last_scanned_on'] = timeconvert(
                                (tz.localize(datetime.now()) - report.scanned_on).total_seconds())
            dat["Host"] = str(ip)
            dat["id"] = host.host_id
            i += 1
            res[i] = dat
    except Exception as e:
        print(e)
    
    return render(request, "view_reports.html" , {"result" : res, "host_id":request.GET.get("host_id")})


def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            # username = form.cleaned_data.get('username')
            # raw_password = form.cleaned_data.get('password1')
        return render(request, 'signup.html', {'success': 'true', 'form': form})
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})


@login_required
def updateHost(request):

    s = request.GET.get('secure_proxy')
    u = request.GET.get('unsecure_proxy')
    config = Settings.objects.filter().last()

    if len(s) == 0:
        secure_proxy = str(config.secure_proxy_ip)+":" + \
            str(config.secure_proxy_port)
    else:
        secure_proxy = s

    if len(u) == 0:
        unsecure_proxy = str(config.unsecure_proxy_ip)+":" + \
            str(config.unsecure_proxy_port)
    else:
        unsecure_proxy = u

    updateHostinDB.delay(request.GET.get('host_id'),
                         request.user.username,
                         request.GET.get('host_ip'),
                         request.GET.get('hostname'),
                         request.GET.get('provider'),
                         request.GET.get('full_scan_flag'),
                         request.GET.get('secure_ports'),
                         request.GET.get('open_ports'),
                         secure_proxy,
                         unsecure_proxy)

    return HttpResponse("Success")


@login_required
def deleteHost(request):
    Host.objects.filter(host_id=int(request.GET.get("host_id"))).delete()
    return HttpResponse("Success")


def changePeriod(
    minutes='*',
    hours='*',
    day_of_week='*',
    day_of_month='*',
    month_of_year='*'
):

    PeriodicTask.objects.filter().delete()

    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute=minutes,
        hour=hours,
        day_of_week=day_of_week,
        day_of_month=day_of_month,
        month_of_year=month_of_year
    )

    PeriodicTask.objects.update_or_create(
        crontab=schedule,
        name='Scan_All_Hosts',
        task='OpenPorts.tasks.scanAllHosts',
    )

@login_required
def loadDashboard(request):

    tz = pytz.timezone("Asia/Calcutta")

    hosts = Host.objects.filter(
        added_by=User.objects.get(username=request.user.username))
    total_secured_ports = 0
    total_open_ports = 0
    total_closed_ports = 0
    total_public_ports = 0
    last_secure_time = ""
    last_open_time = ""
    insecured_hosts = {}
    inaccessible_hosts = {}
    for host in hosts:
        secure_port_results = SecurePortResult.objects.filter(
            added_by=User.objects.get(username=request.user.username),
            host=host
        ).last()
        secure_ports = SecuredPort.objects.filter(
            added_by=User.objects.get(username=request.user.username),
            host=host
        ).last()

        open_port_results = OpenPortResult.objects.filter(
            added_by=User.objects.get(username=request.user.username),
            host=host
        ).last()
        open_ports = OpenPort.objects.filter(
            added_by=User.objects.get(username=request.user.username),
            host=host
        ).last()

        if len(secure_port_results.unsecure_open_ports) > 0:
            total_open_ports += len(secure_port_results.unsecure_open_ports.split(","))
            insecured_hosts[host.ip] = timeconvert(
                (tz.localize(datetime.now()) - secure_port_results.scanned_on).total_seconds())

        if len(secure_ports.secured_ports) > 0:
            total_secured_ports += len(secure_ports.secured_ports.split(","))

        if len(open_port_results.closed_ports) > 0:
            total_closed_ports += len(open_port_results.closed_ports.split(","))
            inaccessible_hosts[host.ip] = timeconvert(
                (tz.localize(datetime.now()) - open_port_results.scanned_on).total_seconds())

        if len(open_ports.unsecured_ports) > 0:
            total_public_ports += len(open_ports.unsecured_ports.split(","))

        last_secure_time = timeconvert(
            (tz.localize(datetime.now()) - secure_port_results.scanned_on).total_seconds())
        last_open_time = timeconvert(
            (tz.localize(datetime.now()) - open_port_results.scanned_on).total_seconds())
    try:
        percent_open = int((total_closed_ports / total_public_ports) * 100)
    except:
        percent_open = 0

    try:
        percent_secured = int((total_open_ports/total_secured_ports) * 100)
    except:
        percent_secured = 0

    context = {
        'totalOpenPorts': total_open_ports,
        'totalSecuredPorts': total_secured_ports,
        'percentSecure': percent_secured,
        'totalClosedPorts': total_closed_ports,
        'totalPublicPorts': total_public_ports,
        'percentOpen': percent_open,
        'lastSecureCheck': last_secure_time,
        'lastOpenCheck': last_open_time,
        'insecuredHosts': insecured_hosts,
        'inaccessibleHosts': inaccessible_hosts
    }

    return render(request, 'dashboard.html', context)


def timeconvert(sec):
    seconds = int(sec)
    if seconds > 59:
        minutes = int(seconds/60)
        if minutes > 59:
            hours = int(minutes/60)
            minutes = minutes % 60
            if hours > 23:
                days = int(hours/24)
                hours = hours % 24
                time = str(days) + " days " + str(hours) + " hours" + " ago"
                return time
            time = str(hours) + " hours " + str(minutes) + " minutes" + " ago"
            return time
        time = str(minutes) + " minutes" + " ago"
        return time
    time = str(seconds) + " seconds" + " ago"
    return time


@login_required
def loadScanReport(request):
    tz = pytz.timezone("Asia/Calcutta")

    stat = ScanStatus.objects.filter().last()
    full_scan_stat = FullScanStatus.objects.filter().last()

    try:
        secure_scan_time = timeconvert(
            (
                tz.localize(datetime.now()) - stat.secure_scan_started_on
            ).total_seconds()
        )
    except:
        secure_scan_time = 0

    try:
        open_scan_time = timeconvert(
            (
                tz.localize(datetime.now()) - stat.open_scan_started_on
            ).total_seconds()
        )
    except:
        open_scan_time = 0

    try:
        full_scan_time = timeconvert(
            (
                tz.localize(datetime.now()) - full_scan_stat.started_on
            ).total_seconds()
        )
    except:
        full_scan_time = 0

    try:
        context = {
            'secureScanStatus': stat.secure_scan_status,
            'openScanStatus': stat.open_scan_status,
            'secureScanTime': secure_scan_time,
            'openScanTime': open_scan_time,
            'fullScanTime': full_scan_time,
            'fullScanStatus': full_scan_stat.scan_status
        }
        return render(request, 'scanreport.html', context)
    except:
        return HttpResponse('<div class="container">\
                                <div class="alert alert-danger alert-dismissible">\
                                <button type="button" class="close" data-dismiss="alert">&times;</button>\
                                <strong>Oops!</strong> No Host Added!\
                                </div></div>')


@login_required
def securePortReport(request):
    res_id = request.GET.get('res_id')

    res = {}
    i = 1
    try:
        print("\n",res_id)
        secure_res = SecurePortResult.objects.get(res_id = int(res_id))
        secure = SecuredPort.objects.filter(
            host=secure_res.host).last()
        if len(secure.secured_ports) > 0:
            ports = [int(x.strip()) for x in secure.secured_ports.split(",")]
        else:
            ports = []
       
        try:
            secureports = [int(x.strip())
                            for x in secure_res.secure_open_ports.split(",")]
        except:
            secureports = []

        try:
            unsecureports = [int(x.strip())
                                for x in secure_res.unsecure_open_ports.split(",")]
        except:
            unsecureports = []

        try:
            secureclosedports = [int(x.strip())
                                    for x in secure_res.secure_closed_ports.split(",")]
        except:
            secureclosedports = []

        secureports = list(set(secureports)-set(unsecureports))
        for port in ports:
            host_dic = {}
            if port in secureports:
                tz = pytz.timezone("Asia/Calcutta")
                t = secure_res.scanned_on
                host_dic["ip"] = secure_res.host.ip
                host_dic["port"] = port
                host_dic["issecured"] = 1
                host_dic["lastchecked"] = timeconvert(
                    (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
                host_dic["insecure"] = len(unsecureports)
                host_dic["lastbreach"] = lastBreach(secure_res.host, port)

            elif port in unsecureports:
                tz = pytz.timezone("Asia/Calcutta")
                t = secure_res.scanned_on
                host_dic["ip"] = secure_res.host.ip
                host_dic["port"] = port
                host_dic["issecured"] = 0
                host_dic["lastbreach"] = "None"
                host_dic["lastchecked"] = timeconvert(
                    (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
                host_dic["insecure"] = len(unsecureports)
                
            elif port in secureclosedports:
                tz = pytz.timezone("Asia/Calcutta")
                t = secure_res.scanned_on
                host_dic["ip"] = secure_res.host.ip
                host_dic["port"] = port
                host_dic["issecured"] = 2
                host_dic["lastbreach"] = "None"
                host_dic["lastchecked"] = timeconvert(
                    (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
                host_dic["insecure"] = len(unsecureports)
            if bool(host_dic):
                res[i] = host_dic
                i += 1

    except Exception as e:
        print("\n", e, "\n")

    data = []
    for i in res:
        data.append(res[i])

    return render(request, "secure_port_report.html", {"secure": res, 'csv': str(data), 'host':str(secure_res.host.ip)})


@login_required
def securePortReports(request):
    ip = request.GET.get('host')
    res = {}
    i = 1
    try:
        print("\n"*3, ip, "\n")
        secure_res_all = SecurePortResult.objects.filter(host = Host.objects.get(ip = str(ip)))

        for secure_res in secure_res_all:
            dat = {}
            tz = pytz.timezone("Asia/Calcutta")
            dat['id'] = i
            dat['ip'] = str(ip)
            dat["lastchecked"] = timeconvert(
                (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
            dat['res_id'] = str(secure_res.res_id)
            res[i] = dat
            i+=1

    except Exception as e:
        print("\n", e, "\n")

    return render(request, "secure_port_reports.html", {"secure": res})

@login_required
def secureAllhost(request):
    hosts = Host.objects.filter(
        added_by=User.objects.get(
            username=request.user.username))

    res = {}
    i = 1
    for host in hosts:
        try:
            tz = pytz.timezone("Asia/Calcutta")
            print("\n"*3, host.host_id, "\n")
            secure_res = SecurePortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()
            host_dic = {}
            host_dic['id'] = host.host_id
            host_dic['ip'] = str(host.ip)
            host_dic['scanned_on'] = timeconvert(
                            (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
            res[i] = host_dic
            i+=1
        except Exception as e:
            print("\n", e, "\n")

    return render(request, "secureAllHost.html", {"secure": res})


@login_required
def add_filters(request):
    ips = request.GET.get("ips")
    status_good = request.GET.get("status_good")
    status_bad = request.GET.get("status_bad")
    Inaccessible = request.GET.get("inaccessible")
    Insecure = request.GET.get("insecure")
    Secure = request.GET.get("secure")
    Accessible = request.GET.get("accessible")

    print("\n", Inaccessible, Insecure, Secure, "\n")

    hosts = Host.objects.filter(
        added_by=User.objects.get(
            username=request.user.username))

    res = {}
    filters = {}
    for host in hosts:
        try:
            host_dic = {}

            secure_res = SecurePortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()
            open_res = OpenPortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()

            host_dic["ip"] = str(host.ip)

            try:
                if len(secure_res.secure_open_ports) > 0:
                    secure_open = [int(x.strip())
                                   for x in secure_res.secure_open_ports.split(",")]
                else:
                    raise Exception

            except:
                secure_open = []

            try:
                if len(secure_res.unsecure_open_ports) > 0:
                    unsecure_open = [int(x.strip())
                                     for x in secure_res.unsecure_open_ports.split(",")]
                else:
                    raise Exception
            except:
                unsecure_open = []

            host_dic["secure_ports"] = len(
                set(secure_open) - set(unsecure_open))

            try:
                if len(secure_res.unsecure_open_ports) > 0:
                    host_dic["unsecure_ports"] = len(
                        [int(x.strip())
                         for x in secure_res.unsecure_open_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                host_dic["unsecure_ports"] = 0

            try:
                if len(secure_res.secure_closed_ports) > 0:
                    secure_closed = len(
                        [int(x.strip())
                         for x in secure_res.secure_closed_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                secure_closed = 0

            try:
                if len(open_res.closed_ports) > 0:
                    open_closed = len(
                        [int(x.strip())
                         for x in open_res.closed_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                open_closed = 0

            host_dic["inaccessible"] = secure_closed + open_closed

            try:
                if len(open_res.open_ports) > 0:
                    host_dic["open_ports"] = len(
                        [int(x.strip())
                         for x in open_res.open_ports.split(",")]
                    )
                else:
                    raise Exception
            except:
                host_dic["open_ports"] = 0

            host_dic["status"] = 0 if host_dic["unsecure_ports"] > 0 else 1

            res[host.host_id] = host_dic
        except Exception as e:
            print(e)
    if len(ips) > 0:
        ip_list = [str(x).strip() for x in ips.split(",")]
        res = filter_ip(res, ip_list)
    # print("\n", res, "\n")
    if status_good == 'true' and status_bad == 'true':
        pass
    elif status_good == 'true' and status_bad == 'false':
        res = status(res, 1)
    elif status_good == 'false' and status_bad == 'true':
        res = status(res, 0)

    if len(Inaccessible) > 0:
        res = inaccessible(res, int(Inaccessible.split(":")[1]),
                           Inaccessible.split(":")[0])

    if len(Insecure) > 0:
        res = insecure(res, int(Insecure.split(":")[1]),
                       Insecure.split(":")[0])

    if len(Secure) > 0:
        res = secure(res, int(Secure.split(":")[1]),
                     Secure.split(":")[0])

    if len(Accessible) > 0:
        res = accessible(res, int(Accessible.split(":")[1]),
                         Accessible.split(":")[0])

    filters["ips"] = ips
    filters["status_good"] = status_good
    filters["status_bad"] = status_bad
    if len(Inaccessible) > 0:
        filters["inaccessible"] = Inaccessible.split(":")[2]
        filters["inaccessible_select"] = Inaccessible.split(":")[0]
        filters["inaccessible_text"] = int(Inaccessible.split(":")[1])
    if len(Insecure) > 0:
        filters["insecure"] = Insecure.split(":")[2]
        filters["insecure_select"] = Insecure.split(":")[0]
        filters["insecure_text"] = int(Insecure.split(":")[1])
    if len(Secure) > 0:
        filters["secure"] = Secure.split(":")[2]
        filters["secure_select"] = Secure.split(":")[0]
        filters["secure_text"] = int(Secure.split(":")[1])
    if len(Accessible) > 0:
        filters["accessible"] = Accessible.split(":")[2]
        filters["accessible_select"] = Accessible.split(":")[0]
        filters["accessible_text"] = int(Accessible.split(":")[1])

    return render(request, "view_All_Hosts.html", {"result_filters": res,
                                                   "filters": filters})


def filter_ip(res, ip_list):
    dat = {}
    for v in res:
        try:
            if res[v]['ip'] in ip_list:
                dat[v] = res[v]
            else:
                raise Exception
        except:
            pass
    return dat


def status(res, status):
    dat = {}
    for v in res:
        try:
            if res[v]['status'] == status:
                dat[v] = res[v]
            else:
                raise Exception
        except:
            pass
    return dat


def inaccessible(res, value, action):
    dat = {}
    if action == "More Than":
        for v in res:
            try:
                if res[v]['inaccessible'] > value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Less Than":
        for v in res:
            try:
                if res[v]['inaccessible'] < value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Equal To":
        for v in res:
            try:
                if res[v]['inaccessible'] == value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat


def accessible(res, value, action):
    dat = {}
    if action == "More Than":
        for v in res:
            try:
                if res[v]['open_ports'] > value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Less Than":
        for v in res:
            try:
                if res[v]['open_ports'] < value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Equal To":
        for v in res:
            try:
                if res[v]['open_ports'] == value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat


def insecure(res, value, action):
    dat = {}
    if action == "More Than":
        for v in res:
            try:
                if res[v]['unsecure_ports'] > value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Less Than":
        for v in res:
            try:
                if res[v]['unsecure_ports'] < value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Equal To":
        for v in res:
            try:
                if res[v]['unsecure_ports'] == value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat


def secure(res, value, action):
    dat = {}
    if action == "More Than":
        for v in res:
            try:
                if res[v]['secure_ports'] > value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Less Than":
        for v in res:
            try:
                if res[v]['secure_ports'] < value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Equal To":
        for v in res:
            try:
                if res[v]['secure_ports'] == value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat


def lastBreach(host, port):
    time = "None"
    tz = pytz.timezone("Asia/Calcutta")

    secure_res = SecurePortResult.objects.filter(
            host=Host.objects.get(host_id=host.host_id))
    

    for secure in secure_res:
        unsecureports = []
        try:
            unsecureports = [int(x.strip())
                             for x in secure.unsecure_open_ports.split(",")]
        except:
            pass
        print("\n"*5, unsecureports, secure.res_id, "\n"*5)
        if port in unsecureports:
            time = timeconvert(
                (tz.localize(datetime.now()) - secure.scanned_on).total_seconds())
            return time

    return time


@login_required
def add_filters_secured(request):
    ips = request.GET.get("ips")
    secured = request.GET.get("secured")
    insecured = request.GET.get("insecured")
    insecure_1 = request.GET.get("insecure_1")
    print("\n"*5, ips, secured, insecured, "\n"*3)

    hosts = Host.objects.filter(
        added_by=User.objects.get(
            username=request.user.username))

    res = {}
    filters = {}
    i = 1
    for host in hosts:
        try:
            print("\n"*3, host.host_id, "\n")
            secure_res_all = SecurePortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id))
            secure = SecuredPort.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()
            ports = [int(x.strip()) for x in secure.secured_ports.split(",")]

            for secure_res in secure_res_all:
                try:
                    secureports = [int(x.strip())
                                   for x in secure_res.secure_open_ports.split(",")]
                except:
                    secureports = []

                try:
                    unsecureports = [int(x.strip())
                                     for x in secure_res.unsecure_open_ports.split(",")]
                except:
                    unsecureports = []

                try:
                    secureclosedports = [int(x.strip())
                                         for x in secure_res.secure_closed_ports.split(",")]
                except:
                    secureclosedports = []

                # print("\n", time.time()-(time.mktime(t.timetuple()) + t.microsecond/1E6), "\n")
                secureports = list(set(secureports)-set(unsecureports))
                for port in ports:
                    host_dic = {}
                    if port in secureports:
                        tz = pytz.timezone("Asia/Calcutta")
                        t = secure_res.scanned_on
                        host_dic["ip"] = host.ip
                        host_dic["port"] = port
                        host_dic["issecured"] = 1
                        host_dic["lastchecked"] = timeconvert(
                            (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
                        host_dic["insecure"] = len(unsecureports)
                        host_dic["lastbreach"] = lastBreach(host, port, True)
                        res[i] = host_dic
                        i += 1
                    elif port in unsecureports:
                        tz = pytz.timezone("Asia/Calcutta")
                        t = secure_res.scanned_on
                        host_dic["ip"] = host.ip
                        host_dic["port"] = port
                        host_dic["issecured"] = 0
                        host_dic["lastbreach"] = "None"
                        host_dic["lastchecked"] = timeconvert(
                            (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
                        host_dic["insecure"] = len(unsecureports)
                        if bool(host_dic):
                            res[i] = host_dic
                            i += 1
                    elif port in secureclosedports:
                        tz = pytz.timezone("Asia/Calcutta")
                        t = secure_res.scanned_on
                        host_dic["ip"] = host.ip
                        host_dic["port"] = port
                        host_dic["issecured"] = 2
                        host_dic["lastbreach"] = "None"
                        host_dic["lastchecked"] = timeconvert(
                            (tz.localize(datetime.now()) - secure_res.scanned_on).total_seconds())
                        host_dic["insecure"] = len(unsecureports)
                        if bool(host_dic):
                            res[i] = host_dic
                            i += 1

        except Exception as e:
            print("\n", e, "\n")

    if len(ips) > 0:
        ip_list = [str(x).strip() for x in ips.split(",")]
        res = filter_ip_secured(res, ip_list)
    # print("\n", res, "\n")
    if secured == 'true' and insecured == 'true':
        pass
    elif secured == 'true' and insecured == 'false':
        res = status_secured(res, 1)
    elif secured == 'false' and insecured == 'true':
        res = status_secured(res, 0)

    if len(insecure_1) > 0:
        res = insecure_12(res, int(insecure_1.split(":")[1]),
                          insecure_1.split(":")[0])

    filters["ips"] = ips
    filters["secured"] = secured
    filters["insecured"] = insecured
    if len(insecure_1) > 0:
        filters["insecure"] = insecure_1.split(":")[2]
        filters["insecure_select"] = insecure_1.split(":")[0]
        filters["insecure_text"] = int(insecure_1.split(":")[1])

    data = []
    for i in res:
        data.append(res[i])
    return render(request, "secure_port_report.html", {"secure_filters": res,
                                                       "filters": filters,
                                                       "csv": str(data)})


def filter_ip_secured(res, ip_list):
    dat = {}
    for v in res:
        try:
            if res[v]['ip'] in ip_list:
                dat[v] = res[v]
            else:
                raise Exception
        except:
            pass
    return dat


def status_secured(res, status):
    dat = {}
    for v in res:
        try:
            if res[v]['issecured'] == status:
                dat[v] = res[v]
            else:
                raise Exception
        except:
            pass
    return dat


def insecure_12(res, value, action):
    dat = {}
    if action == "More Than":
        for v in res:
            try:
                if res[v]['insecure'] > value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Less Than":
        for v in res:
            try:
                if res[v]['insecure'] < value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Equal To":
        for v in res:
            try:
                if res[v]['insecure'] == value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat


@login_required
def add_filters_opened(request):
    ips = request.GET.get("ips")
    secured = request.GET.get("secured")
    insecured = request.GET.get("insecured")
    insecure_1 = request.GET.get("insecure_1")
    print("\n"*5, ips, secured, insecured, "\n"*3)

    hosts = Host.objects.filter(
        added_by=User.objects.get(
            username=request.user.username))

    res = {}
    filters = {}
    i = 1
    for host in hosts:
        try:
            print("\n"*3, host.host_id, "\n")
            open_res_all = OpenPortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id))
            open1 = OpenPort.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()
            ports = [int(x.strip()) for x in open1.unsecured_ports.split(",")]
            for open_res in open_res_all:
                try:
                    openports = [int(x.strip())
                                 for x in open_res.open_ports.split(",")]
                except:
                    openports = []

                try:
                    closedports = [int(x.strip())
                                   for x in open_res.closed_ports.split(",")]
                except:
                    closedports = []

                # print("\n", time.time()-(time.mktime(t.timetuple()) + t.microsecond/1E6), "\n")
                openports = list(set(openports)-set(closedports))
                for port in ports:
                    host_dic = {}
                    if port in openports:
                        tz = pytz.timezone("Asia/Calcutta")
                        t = open_res.scanned_on
                        host_dic["ip"] = host.ip
                        host_dic["port"] = port
                        host_dic["issecured"] = 1
                        host_dic["lastchecked"] = timeconvert(
                            (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
                        host_dic["insecure"] = 0
                        host_dic["lastbreach"] = lastBreach(host, port)
                        print("\n", t, "\n")
                        if bool(host_dic):
                            res[i] = host_dic
                            i += 1

                    elif port in closedports:
                        tz = pytz.timezone("Asia/Calcutta")
                        t = open_res.scanned_on
                        host_dic["ip"] = host.ip
                        host_dic["port"] = port
                        host_dic["issecured"] = 0
                        host_dic["lastbreach"] = "None"
                        host_dic["lastchecked"] = timeconvert(
                            (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
                        host_dic["insecure"] = len(closedports)
                        if bool(host_dic):
                            res[i] = host_dic
                            i += 1

        except Exception as e:
            print("\n123", e, "\n")
    if len(ips) > 0:
        ip_list = [str(x).strip() for x in ips.split(",")]
        res = filter_ip_opened(res, ip_list)
    # print("\n", res, "\n")
    if secured == 'true' and insecured == 'true':
        pass
    elif secured == 'true' and insecured == 'false':
        res = status_opened(res, 1)
    elif secured == 'false' and insecured == 'true':
        res = status_opened(res, 0)

    if len(insecure_1) > 0:
        res = insecure_12(res, int(insecure_1.split(":")[1]),
                          insecure_1.split(":")[0])

    filters["ips"] = ips
    filters["secured"] = secured
    filters["insecured"] = insecured
    if len(insecure_1) > 0:
        filters["insecure"] = insecure_1.split(":")[2]
        filters["insecure_select"] = insecure_1.split(":")[0]
        filters["insecure_text"] = int(insecure_1.split(":")[1])

    print("\n"*5, filters, res, "\n"*3)
    data = []
    for i in res:
        data.append(res[i])
    return render(request, "open_port_report.html", {"secure_filters": res,
                                                     "filters": filters,
                                                     "csv": str(data)})


def filter_ip_opened(res, ip_list):
    dat = {}
    for v in res:
        try:
            if res[v]['ip'] in ip_list:
                dat[v] = res[v]
            else:
                raise Exception
        except:
            pass
    return dat


def status_opened(res, status):
    dat = {}
    for v in res:
        try:
            if res[v]['issecured'] == status:
                dat[v] = res[v]
            else:
                raise Exception
        except:
            pass
    return dat


def insecure_13(res, value, action):
    dat = {}
    if action == "More Than":
        for v in res:
            try:
                if res[v]['insecure'] > value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Less Than":
        for v in res:
            try:
                if res[v]['insecure'] < value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat
    if action == "Equal To":
        for v in res:
            try:
                if res[v]['insecure'] == value:
                    dat[v] = res[v]
                else:
                    raise Exception
            except:
                pass
        return dat


def add_filters_view_report(request):
    secured = request.GET.get("secured")
    insecure = request.GET.get("insecure")
    opened = request.GET.get("open")
    inaccessible = request.GET.get("inaccessible")

    host = Host.objects.get(host_id=request.GET.get("host_id"))
    sec = SecuredPort.objects.get(host=host)
    op = OpenPort.objects.get(host=host)
    sec_res = SecurePortResult.objects.filter(host=host).last()
    op_res = OpenPortResult.objects.filter(host=host).last()
    if len(sec_res.secure_open_ports) > 0:
        secure = [int(x.strip()) for x in sec_res.secure_open_ports.split(",")]
    else:
        secure = []

    if len(sec_res.unsecure_open_ports) > 0:
        unsecure = [int(x.strip())
                    for x in sec_res.unsecure_open_ports.split(",")]
    else:
        unsecure = []

    if len(op_res.open_ports) > 0:
        open = [int(x.strip()) for x in op_res.open_ports.split(",")]
    else:
        open = []

    res = {}
    i = 0
    if len(sec.secured_ports) > 0:
        secure_port = [int(x.strip()) for x in sec.secured_ports.split(",")]
    else:
        secure_port = []

    if len(op.unsecured_ports) > 0:
        open_port = [int(x.strip()) for x in op.unsecured_ports.split(",")]
    else:
        open_port = []

    for port in secure_port:
        dat = {}
        if port in secure:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Secured"
        elif port in unsecure:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Unsecured"
        else:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Inaccessible"
        res[i] = dat
        i += 1
    for port in open_port:
        dat = {}
        if port in open:
            dat["host"] = host.ip
            dat["port"] = port
            dat["status"] = "Open"
        else:
            dat["host"] = host
            dat["port"] = port
            dat["status"] = "Inaccessible"
        res[i] = dat
        i += 1

    res = applyFilters(secured, insecure, opened, inaccessible, res)
    filters = {"secured":secured,"insecure":insecure,"open":opened,"inaccessible":inaccessible}
    csv = []
    for i in res:
        csv.append(res[i])
    return render(request, "view_report.html" , {"result_filters" : res, "filters": filters,"host_id":request.GET.get("host_id"),'csv':str(csv)})


def applyFilters(secured, insecure, opened, inaccessible, res):
    dat = {}
    for key in res:
        if secured == 'true' and res[key]['status'] == "Secured":
            dat[key] = res[key]
        elif insecure == 'true' and res[key]['status'] == "Unsecured":
            dat[key] = res[key]
        elif opened == 'true' and res[key]['status'] == "Open":
            dat[key] = res[key]
        elif inaccessible == 'true' and res[key]['status'] == "Inaccessible":
            dat[key] = res[key]
        elif secured == "false" and insecure == "false" and opened == "false" and inaccessible == "false":
            dat[key] = res[key]
    return dat


@login_required
def fullScanReport(request):
    hosts = Host.objects.filter(
                                added_by=User.objects.get(
                                username=request.user.username))    
    res = {}
    tz = pytz.timezone("Asia/Calcutta")
    i=0
    try :
        for host in hosts:
            dat = {}
            dat['Host'] = str(host.ip)
            full_scan = FullScanResult.objects.filter(host = host).last()
            scanned_on = full_scan.started_on
            dat['last_scanned_on'] = timeconvert(
                                (tz.localize(datetime.now()) - scanned_on).total_seconds())
            i+=1
            res[i] = dat
    except:
        pass

    return render(request, 'full_scan_result.html' , {"result": res})


@login_required
def viewAllScans(request):
    host = request.GET.get("host")
    tz = pytz.timezone("Asia/Calcutta")
    res = {}
    print("\n"*3,host)
    try:
        full_scans = FullScanResult.objects.filter(host = Host.objects.get(ip = str(host)))
        i = 0
        for full_scan in full_scans:
            dat = {}
            dat['last_scanned_on'] = timeconvert(
                                (tz.localize(datetime.now()) - full_scan.started_on).total_seconds())
            dat["Host"] = str(host)
            dat["id"] = full_scan.scan_id
            i+=1
            dat["totaltime"] = full_scan.runtime
            res[i] = dat
    except:
        pass
    return render(request, 'full_scan_result.html' , {"resultAllScans": res})


@login_required
def viewScan(request):
    id = request.GET.get("id")
    print(id)
    try:
        scan = FullScanResult.objects.get(scan_id = int(id))
        res = {}
        i=1
        if len(scan.open_ports) > 0:
            open_ports = [int(x.strip()) for x in scan.open_ports.split(",")]
        else:
            open_ports = []
        if len(scan.close_ports) > 0:
            close_ports = [int(x.strip()) for x in scan.close_ports.split(",")]
        else:
            close_ports = []
        
        for port in open_ports:
            dat = {}
            dat["ip"] = scan.host.ip
            dat["port"] = port
            dat["status"] = "Open Port"
            res[i] = dat
            i+=1
    except:
        pass
    csv = []
    for i in res:
        csv.append(res[i])
    return render(request, 'view_scan.html', {'result':res,'csv':str(csv),"host":str(scan.host.ip)})


@login_required
def openPortReport(request):
    res_id = request.GET.get('res_id')
    print(type(res_id))
    res = {}
    i = 1
    open_res = OpenPortResult.objects.get(res_id = int(res_id))

    try:
        print("\n",res_id)
        open_port = OpenPort.objects.filter(
            host=open_res.host).last()
        if len(open_port.unsecured_ports) > 0:
            ports = [int(x.strip()) for x in open_port.unsecured_ports.split(",")]
        else:
            ports = []
       
        try:
            openports = [int(x.strip())
                            for x in open_res.open_ports.split(",")]
        except:
            openports = []

        print("\n", openports, ports, "\n")
        for port in ports:
            host_dic = {}
            if port in openports:
                tz = pytz.timezone("Asia/Calcutta")
                host_dic['id'] = i
                host_dic["ip"] = open_res.host.ip
                host_dic["port"] = port
                host_dic["isaccessible"] = 1
                host_dic["lastinaccessible"] = lastInaccessible(open_res.host, port)
                host_dic["lastchecked"] = timeconvert(
                    (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
                host_dic["accessible"] = len(ports)-len(openports)

            else:
                tz = pytz.timezone("Asia/Calcutta")
                host_dic['id'] = i
                host_dic["ip"] = open_res.host.ip
                host_dic["port"] = port
                host_dic["isaccessible"] = 0
                host_dic["lastinaccessible"] = "None"
                host_dic["lastchecked"] = timeconvert(
                    (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
                host_dic["accessible"] = len(ports)-len(openports)
            if bool(host_dic):
                res[i] = host_dic
                i += 1

    except Exception as e:
        print("\n", e, "\n")

    data = []
    for i in res:
        data.append(res[i])

    return render(request, "open_port_report.html", {"open": res, 'csv': str(data), 'host':str(open_res.host.ip)})


@login_required
def openPortReports(request):
    ip = request.GET.get('host')
    res = {}
    i = 1
    try:
        print("\n"*3, ip, "\n")
        open_res_all = OpenPortResult.objects.filter(host = Host.objects.get(ip = str(ip)))

        for open_res in open_res_all:
            dat = {}
            tz = pytz.timezone("Asia/Calcutta")
            dat['id'] = i
            dat['ip'] = str(ip)
            dat["lastchecked"] = timeconvert(
                (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
            dat['res_id'] = str(open_res.res_id)
            res[i] = dat
            i+=1

    except Exception as e:
        print("\n", e, "\n")

    return render(request, "open_port_reports.html", {"open": res})

@login_required
def openAllhost(request):
    hosts = Host.objects.filter(
        added_by=User.objects.get(
            username=request.user.username))

    res = {}
    i = 1
    for host in hosts:
        try:
            tz = pytz.timezone("Asia/Calcutta")
            print("\n"*3, host.host_id, "\n")
            open_res = OpenPortResult.objects.filter(
                host=Host.objects.get(host_id=host.host_id)).last()
            host_dic = {}
            host_dic['id'] = host.host_id
            host_dic['ip'] = str(host.ip)
            host_dic['scanned_on'] = timeconvert(
                            (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
            res[i] = host_dic
            i+=1
        except Exception as e:
            print("\n", e, "\n")

    return render(request, "openAllHost.html", {"open": res})


def lastInaccessible(host, port):
    time = "None"
    tz = pytz.timezone("Asia/Calcutta")

    open_ress = OpenPortResult.objects.filter(
            host=Host.objects.get(host_id=host.host_id))
    

    for open_res in open_ress:
        closeports = []
        try:
            closeports = [int(x.strip())
                             for x in open_res.closed_ports.split(",")]
        except:
            pass
        print(closeports)
        if port in closeports:
            time = timeconvert(
                (tz.localize(datetime.now()) - open_res.scanned_on).total_seconds())
            return time

    return time