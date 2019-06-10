from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^home$', views.home, name='home'),
    url(r'^home/scan', views.index, name='index'),
    url(r'^home/fetch', views.fetch, name='fetch'),
    url(r'^home/view_scans', views.view_scans, name='view_scans'),
    url(r'^home/addhost', views.addhost, name="addhost"),
    url(r'^home/addnewhost', views.addnewhost, name="addnewhost")
]
