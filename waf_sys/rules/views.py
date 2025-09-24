from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotFound
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from customers.models import Client
from .models import WAFRule, BlockedRequest
from .forms import WAFRuleForm
import json

@login_required
def rules_list(request):
    rules = WAFRule.objects.select_related("client").all()
    return render(request, "rules_list.html", {"rules": rules})

@login_required
def rules_create(request):
    if request.method == "POST":
        form = WAFRuleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("rules:rules_list")
    else:
        form = WAFRuleForm()
    return render(request, "rules_create.html", {"form": form})

@require_GET
def api_rules(request):
    client_host = request.GET.get("client_host")
    if not client_host:
        return HttpResponseBadRequest("Missing client_host parameter")
    try:
        client = Client.objects.get(host=client_host)
    except Client.DoesNotExist:
        # It's better to return a 404 for security reasons
        return HttpResponseNotFound("Client configuration not found")

    rules = list(
        WAFRule.objects.filter(client=client, is_active=True).values("rule_type", "value")
    )
    return JsonResponse({"client_name": client.name, "target_url": client.target_url, "rules": rules})

@csrf_exempt
@require_POST
def api_log_blocked_request(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
        client_host = data.get("client_host")
        client = Client.objects.get(host=client_host)
        BlockedRequest.objects.create(
            client=client,
            ip_address=data.get("ip_address","0.0.0.0"),
            request_path=data.get("request_path",""),
            user_agent=data.get("user_agent",""),
            reason=data.get("reason",""),
        )
        return JsonResponse({"status": "ok"})
    except Client.DoesNotExist:
        return HttpResponseNotFound("Client not found for logging")
    except Exception as e:
        return HttpResponseBadRequest(f"Error: {e}")
