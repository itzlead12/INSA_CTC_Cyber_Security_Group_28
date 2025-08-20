from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, redirect, get_object_or_404
from .models import Client
from .forms import ClientForm

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)

@login_required(login_url="dashboard:login")
@staff_required
def client_list(request):
    clients = Client.objects.all()
    return render(request, "clients_list.html", {"clients": clients})

@login_required(login_url="dashboard:login")
@staff_required
def client_create(request):
    if request.method == "POST":
        form = ClientForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("customers:client_list")
    else:
        form = ClientForm()
    return render(request, "client_form.html", {"form": form})

@login_required(login_url="dashboard:login")
@staff_required
def client_edit(request, pk):
    client = get_object_or_404(Client, pk=pk)
    if request.method == "POST":
        form = ClientForm(request.POST, instance=client)
        if form.is_valid():
            form.save()
            return redirect("customers:client_list")
    else:
        form = ClientForm(instance=client)
    return render(request, "client_form.html", {"form": form})
