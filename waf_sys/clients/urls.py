from django.urls import path
from . import views
from . import api_views 

app_name = 'clients'

urlpatterns = [
    
    path('register/', views.client_register, name='client_register'),
    path('onboarding/<int:pk>/', views.client_onboarding, name='client_onboarding'),
    path('dashboard/', views.client_dashboard_first, name='client_dashboard_first'),
    path('dashboard/<int:pk>/', views.client_dashboard, name='client_dashboard'),
    
    
    path('manage/', views.client_list, name='client_list'),
    #path('manage/new/', views.client_create, name='client_create'),
    path('manage/edit/<int:pk>/', views.client_edit, name='client_edit'),
    path('manage/delete/<int:pk>/', views.client_delete, name='client_delete'),
    path('dashboard/<int:pk>/geo-threats/', views.client_geo_threats, name='client_geo_threats'),
   
    path('dashboard/<int:pk>/analytics/', views.client_analytics, name='client_analytics'),
    path('dashboard/<int:pk>/threats/', views.client_threats, name='client_threats'),
    
     path('api/<int:pk>/stats/', views.client_api_stats, name='client_api_stats'),
     path('api/<int:pk>/threats/', views.client_api_threats, name='client_api_threats'),
     path('api/<int:pk>/geo-threats/', views.client_api_geo_threats, name='client_api_geo_threats'),
     path('api/<int:pk>/traffic/', views.client_api_traffic, name='client_api_traffic'),
     path('api/v1/clients/<str:host>/waf-config/', api_views.ClientWAFConfigAPI.as_view(), name='client_waf_config'),

    path('dashboard/<int:pk>/blocking/', views.client_blocking_management, name='client_blocking_management'),
    path('api/<int:pk>/blocking/settings/', views.update_blocking_settings, name='update_blocking_settings'),
    path('api/<int:pk>/blocking/stats/', views.get_blocking_statistics, name='get_blocking_statistics'),
    path('api/<int:pk>/blocking/quick-block-ip/', views.quick_block_ip, name='quick_block_ip'),
    path('api/<int:pk>/blocking/remove-ip/', views.remove_blocked_ip, name='remove_blocked_ip'),
]
