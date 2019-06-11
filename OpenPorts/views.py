# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from .tasks import scanOpenPorts, addHostToDB

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

    addHostToDB.delay(request.user.username,
                      request.GET.get('host_ip'),
                      request.GET.get('hostname'),
                      request.GET.get('provider'),
                      request.GET.get('secure_ports'),
                      request.GET.get('open_ports'),
                      request.GET.get('secure_proxy'),
                      request.GET.get('unsecure_proxy'))

    return HttpResponse("Success")
