from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.landing_page, name='landing'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('xz3a21rqhe4oo6ox2w31rryga/', views.admin_dashboard, name='admin_dashboard'),
    path('api/stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
   
]
