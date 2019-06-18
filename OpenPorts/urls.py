from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^home$', views.home, name='home'),
    url(r'^home/scan', views.index, name='index'),
    url(r'^home/fetch', views.fetch, name='fetch'),
    url(r'^home/view_scans', views.view_scans, name='view_scans'),
    url(r'^home/addhost', views.addhost, name="addhost"),
    url(r'^home/addnewhost', views.addnewhost, name="addnewhost"),
    url(r'^home/add_settings', views.add_settings, name="add_settings"),
    url(r'^home/new_settings', views.new_settings, name="new_settings"),
    url(r'^home/allhosts', views.allhosts, name="allhosts"),
    url(r'^home/signup$', views.signup, name="signup"),
    url(r'^home/editHost$', views.editHost, name="editHost"),
    url(r'^home/updateHost$', views.updateHost, name="updateHost"),
    url(r'^home/deleteHost$', views.deleteHost, name="deleteHost"),
    url(r'^home/dashboard$', views.loadDashboard, name="loadDashboard")
]
