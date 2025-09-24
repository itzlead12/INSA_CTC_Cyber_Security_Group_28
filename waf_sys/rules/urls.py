from django.urls import path
from . import views

app_name = "rules"

urlpatterns = [
    
    path("", views.rules_list, name="rules_list"),
    path("new/", views.rules_create, name="rules_create"),
    path("api/v1/rules/", views.api_rules, name="api_rules"),
    path("api/v1/blocked_requests/", views.api_log_blocked_request, name="api_log_blocked_request"),
]
