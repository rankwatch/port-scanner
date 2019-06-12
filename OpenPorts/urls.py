from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^home$', views.home, name='home'),
    url(r'^home/scan', views.index, name='index'),
    url(r'^home/fetch', views.fetch, name='fetch'),
    url(r'^home/addhost', views.addhost, name='addhost'),
    url(r'^home/allhost', views.allhost, name='allhost'),
    url(r'^home/view_scans', views.view_scans, name='view_scans'),
    url(r'^home/addnewhost', views.addnewhost, name='addnewhost'),
    url(r'^home/settings', views.add_settings, name="add_settings"),
    url(r'^home/new_setting', views.new_Setting, name="new_Setting"),
    url(r'^home/signup$', views.signup, name="signup"),
    # url(r'^home/signup/signup_details', views.signup_details, name='signup_details')
]
