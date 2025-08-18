from django.urls import path
from . import views

app_name = "customers" #which means clients

urlpatterns = [
    path("", views.client_list, name="client_list"),
    path("new/", views.client_create, name="client_create"),
    path("edit/<int:pk>", views.client_edit, name="client_edit"),
]
