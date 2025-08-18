from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render
from rules.models import BlockedRequest

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)
#dashboard fot th admin
@login_required(login_url="dashboard:login")
@staff_required
def admin_dashboard(request):
    latest = BlockedRequest.objects.select_related("client").order_by("-timestamp")[:50]
    return render(request, "dashboard.html", {"initial": latest})#templates will be addedd for the dashboard
#dashboard for the clientw web owner
@login_required(login_url="dashboard:login")
def client_dashboard(request):
    profile = getattr(request.user, "profile", None)
    client = getattr(profile, "client", None)
    initial = []
    if client:
        initial = client.blocked_requests.order_by("-timestamp")[:50]
    return render(request, "clients_dashboard.html", {"initial": initial, "client": client})#templates will be addedd for the dashboard
