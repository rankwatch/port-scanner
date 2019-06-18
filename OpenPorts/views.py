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

        return render(request, "settings.html", {"result": {
            "Secure": secure_proxy,
            "Unsecure": unsecure_proxy,
            "threads": threads,
            "timeout": timeout,
            "scanfrequency": scanf}
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
    s = Settings(secure_proxy_ip=secure_ip_port[0],
                 unsecure_proxy_ip=unsecure_ip_port[0],
                 secure_proxy_port=secure_ip_port[1],
                 unsecure_proxy_port=unsecure_ip_port[1],
                 threads=request.GET.get("threads"),
                 timeout=request.GET.get("timeout"),
                 schedule=request.GET.get("scanfrequency"))
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

            host_dic["ip"] = host.ip

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
        "secure_proxy_ip": host.secure_proxy_ip,
        "unsecure_proxy_ip": host.unsecure_proxy_ip,
        "open_ports": [str(x.strip()) for x in op.unsecured_ports.split(",")],
        "secure_ports": [str(x.strip()) for x in sec.secured_ports.split(",")]
    }
    return render(request, "add_host_ip.html", {"result": host_dic})


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
                         request.GET.get('secure_ports'),
                         request.GET.get('open_ports'),
                         secure_proxy,
                         unsecure_proxy)

    return HttpResponse("Success")


@login_required
def deleteHost(request):
    Host.objects.filter(host_id=int(request.GET.get("host_id"))).delete()
    return HttpResponse("Success")


def changePeriod(minutes='*', hours='*', day_of_week='*', day_of_month='*', month_of_year='*'):

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

    