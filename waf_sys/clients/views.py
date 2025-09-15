from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, redirect, get_object_or_404
from .models import Client
from .forms import ClientForm

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)



@login_required(login_url="dashboard:login")
@staff_required
def client_create(request):
    if request.method == "POST":
        form = ClientForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("dashboard:client_list")
    else:
        form = ClientForm()
    return render(request, "clients/client_form.html", {"form": form})

@login_required(login_url="dashboard:login")
@staff_required
def client_edit(request, pk):
    client = get_object_or_404(Client, pk=pk)
    if request.method == "POST":
        form = ClientForm(request.POST, instance=client)
        if form.is_valid():
            form.save()
            return redirect("dashboard:client_list")
    else:
        form = ClientForm(instance=client)
    return render(request, "clients/client_form.html", {"form": form})

@login_required(login_url="dashboard:login")
@staff_required
def client_delete(request, pk):
    client = get_object_or_404(Client, pk=pk)
    client.delete()
    return redirect("dashboard:client_list")

@login_required(login_url="dashboard:login")
def client_dashboard(request):
    profile = getattr(request.user, "profile", None)
    client = getattr(profile, "client", None)
    initial = []
    if client:
        initial = client.blocked_requests.order_by("-timestamp")[:50]
    return render(request, "clients/clients_dashboard.html", {"initial": initial, "client": client})




