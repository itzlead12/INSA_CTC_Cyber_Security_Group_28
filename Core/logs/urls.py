from django.urls import path
from . import views

app_name = 'logs'

urlpatterns = [
    # Log viewing
    path('', views.request_logs, name='request_logs'),
    path('threats/', views.threat_analysis, name='threat_analysis'),
    
    # API endpoints
    path('api/<int:log_id>/', views.log_details_api, name='log_details_api'),
    path('api/v1/security-events/', views.log_security_event, name='log_security_event'),
    path('export/', views.export_logs, name='export_logs'),
    path('api/v1/ip-geolocation/<str:ip_address>/', views.get_ip_geolocation, name='ip_geolocation_api'),
]