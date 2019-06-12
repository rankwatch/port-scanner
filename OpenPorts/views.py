# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from .models import Scan
from .tasks import scanOpenPorts
from .tasks import addHostToDB
from .models import settings
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
import ast


@login_required
def home(request):
    print("In HOME")
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
    return render(request, "add_host_ip.html", {"abc": 123})


@login_required
def allhost(request):
    return render(request, "view_All_Hosts.html", {"abc": 123})


@login_required
def addnewhost(request):

    host_ip = request.GET.get('host_ip')
    secure_ports = request.GET.get('secure_ports')
    open_ports = request.GET.get('open_ports')
    s = request.GET.get('secure_proxy')
    u = request.GET.get('unsecure_proxy')
    secure = settings.objects.filter(user=User.objects.get(
        username=str(request.user.username))).last()
    if s == "":

        secure_proxy = str(secure.secure_proxy_ip)+":" + \
            str(secure.secure_proxy_port)
    else:
        secure_proxy = s[0]
    if u == "":
        unsecure_proxy = str(secure.unsecure_proxy_ip)+":" + \
            str(secure.unsecure_proxy_port)
    else:
        unsecure_proxy = u

    print("\n\n\n\n\n", secure_proxy, "\n\n\n\n", unsecure_proxy)
    addHostToDB.delay(request.user.username,
                      host_ip,
                      str(secure_ports),
                      str(open_ports),
                      secure_proxy,
                      unsecure_proxy)

    return HttpResponse("Success")


@login_required
def add_settings(request):
    try:
        user = settings.objects.filter(user=User.objects.get(
            username=str(request.user.username))).last()
        print("\n\n\n\n\n\nhello2\n\n\n")
        secure = str(user.secure_proxy_ip)+":"+str(user.secure_proxy_port)
        unsecure = str(user.unsecure_proxy_ip)+":" + \
            str(user.unsecure_proxy_port)
        print(secure, unsecure)
        return render(request, "settings.html", {"result": {"Secure": secure, "unsecure": unsecure}})
    except:
        print("\n\n\n\n\n\nhello\n\n\n")
        return render(request, "settings.html")


@login_required
def new_Setting(request):
    user = User.objects.get(username=request.user.username)
    secure = request.GET.get('secure_ip-port')
    unsecure = request.GET.get('unsecure_ip-port')
    secure_ip_port = secure.split(":")
    unsecure_ip_port = unsecure.split(":")
    s = settings(user=user, secure_proxy_ip=secure_ip_port[0], unsecure_proxy_ip=unsecure_ip_port[0],
                 secure_proxy_port=secure_ip_port[1], unsecure_proxy_port=unsecure_ip_port[1])
    s.save()

    print(secure, unsecure)
    return HttpResponse("Success")


def signup(request):
    if request.method == 'POST':
            form = UserCreationForm(request.POST)
            if form.is_valid():
                form.save()
                username = form.cleaned_data.get('username')
                raw_password = form.cleaned_data.get('password1')
                user = authenticate(username=username, password=raw_password)
                login(request, user)
                return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})
