from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

app_name = "dashboard"

urlpatterns = [
    path("", views.admin_dashboard, name="admin_dashboard"),
    path('login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path("clients/", views.client_list, name="client_list"),
]
