from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

app_name = "dashboard"

urlpatterns = [
    path("", views.admin_dashboard, name="admin_dashboard"),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path("client/", views.client_dashboard, name="client_dashboard"),
]
