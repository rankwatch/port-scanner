from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^home$', views.home, name='home'),
    url(r'^home/scan$', views.index, name='index'),
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
    url(r'^home/dashboard$', views.loadDashboard, name="loadDashboard"),
    url(r'^home/scanreport$', views.loadScanReport, name="loadScanReport"),
    url(r'^home/securePortReport$', views.securePortReport, name="securePortReport"),
    url(r'^home/openPortReport$', views.openPortReport, name="openPortReport"),
    url(r'^home/fullScanReport$', views.fullScanReport, name="fullScanReport"),
    url(r'^home/viewAllScans$', views.viewAllScans, name="viewAllScans"),
    url(r'^home/viewScan$', views.viewScan, name="viewScan"),
    url(r'^home/add_filters$', views.add_filters, name="add_filters"),
    url(r'^home/add_filters_secured',
        views.add_filters_secured, name="add_filters_secured"),
    url(r'^home/add_filters_opened',
        views.add_filters_opened, name="add_filters_opened"),
    url(r'^home/viewReport$', views.viewReport, name="viewReport"),
    url(r'^home/viewReports$', views.viewReports, name="viewReports"),
    url(r'^home/add_filters_view_report$', views.add_filters_view_report, name="add_filters_view_report")
]
