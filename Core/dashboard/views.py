from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render
from django.contrib.auth import authenticate
from rules.models import BlockedRequest

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)
#dashboard fot th admin
@login_required(login_url="dashboard:login")
@staff_required
def admin_dashboard(request):
    latest = BlockedRequest.objects.select_related("client").order_by("-timestamp")[:50]
    return render(request, "dashboard/dashboard.html", {"initial": latest})#templates will be addedd for the dashboard
#dashboard for the clientw web owner
# the clients dashboard page should stay at the client app
@login_required(login_url="dashboard:login")
@staff_required
def client_list(request):
    clients = Client.objects.all()
    return render(request, "dashboard/clients_list.html", {"clients": clients})

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
    return render(request, "dashboard/login.html")
