from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotFound
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from customers.models import Client
from .models import WAFRule, BlockedRequest
from .forms import WAFRuleForm
import json


from django.contrib.auth.decorators import user_passes_test

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)

def my_rulesets(request,pk):
    client = Client.objects.get(pk=pk, is_active=True)
    client_rulesets = ClientRuleSet.objects.filter(
        client=client, 
        is_active=True
    ).select_related('ruleset')
    
    context = {
        'rulesets': client_rulesets,
        'total_rulesets': client_rulesets.count(),
        'public_rulesets': client_rulesets.filter(is_public=True).count(),
        'active_rulesets': client_rulesets.filter(is_active=True).count(),
    }
    return render(request, 'templates/rules/my_ruleset.html', context)


@login_required
@staff_required
def ruleset_list(request):
    rulesets = RuleSet.objects.all().prefetch_related('rules').order_by('-created_at')
    
    context = {
        'rulesets': rulesets,
        'total_rulesets': rulesets.count(),
        'public_rulesets': rulesets.filter(is_public=True).count(),
        'active_rulesets': rulesets.filter(is_active=True).count(),
    }
    return render(request, 'rules/ruleset_list.html', context)


@login_required
@staff_required
def ruleset_create(request):
    if request.method == 'POST':
        form = RuleSetForm(request.POST)
        if form.is_valid():
            ruleset = form.save(commit=False)
            ruleset.created_by = request.user
            ruleset.save()
            messages.success(request, f'Rule set "{ruleset.name}" created successfully!')
            return redirect('rules:ruleset_detail', pk=ruleset.pk)
    else:
        form = RuleSetForm()
    
    return render(request, 'rules/ruleset_form.html', {
        'form': form,
        'title': 'Create New Rule Set'
    })

@login_required
@staff_required
def ruleset_detail(request, pk):
    ruleset = get_object_or_404(RuleSet, pk=pk)
    rules = ruleset.rules.all().order_by('rule_type', 'severity')
    
    rule_stats = rules.aggregate(
        total=Count('id'),
        active=Count('id', filter=Q(is_active=True)),
        critical=Count('id', filter=Q(severity='critical', is_active=True)),
        high=Count('id', filter=Q(severity='high', is_active=True)),
    )
    
    client_count = ClientRuleSet.objects.filter(ruleset=ruleset, is_active=True).count()
    
    context = {
        'ruleset': ruleset,
        'rules': rules,
        'rule_stats': rule_stats,
        'client_count': client_count,
    }
    return render(request, 'rules/ruleset_detail.html', context)

@login_required
@staff_required
def ruleset_edit(request, pk):
    ruleset = get_object_or_404(RuleSet, pk=pk)
    
    if request.method == 'POST':
        form = RuleSetForm(request.POST, instance=ruleset)
        if form.is_valid():
            ruleset = form.save()
            messages.success(request, f'Rule set "{ruleset.name}" updated successfully!')
            return redirect('rules:ruleset_detail', pk=ruleset.pk)
    else:
        form = RuleSetForm(instance=ruleset)
    
    return render(request, 'rules/ruleset_form.html', {
        'form': form,
        'ruleset': ruleset,
        'title': f'Edit Rule Set: {ruleset.name}'
    })

@login_required
@staff_required
def ruleset_delete(request, pk):
    ruleset = get_object_or_404(RuleSet, pk=pk)
    
    if request.method == 'POST':
        ruleset_name = ruleset.name
        ruleset.delete()
        messages.success(request, f'Rule set "{ruleset_name}" deleted successfully!')
        return redirect('rules:ruleset_list')
    
    return render(request, 'rules/ruleset_confirm_delete.html', {'ruleset': ruleset})

@login_required
@staff_required
def ruleset_import(request):
    if request.method == 'POST':
        form = RuleSetImportForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                ruleset = import_ruleset_from_file(
                    request.FILES['file'],
                    form.cleaned_data['format'],
                    request.user
                )
                messages.success(request, f'Rule set "{ruleset.name}" imported successfully!')
                return redirect('rules:ruleset_detail', pk=ruleset.pk)
            except Exception as e:
                messages.error(request, f'Error importing rule set: {str(e)}')
    else:
        form = RuleSetImportForm()
    
    return render(request, 'rules/ruleset_import.html', {'form': form})

@login_required
@staff_required
def rule_create(request, pk):
    ruleset = get_object_or_404(RuleSet, pk=pk)
    
    if request.method == 'POST':
        form = WAFRuleForm(request.POST)
        if form.is_valid():
            rule = form.save(commit=False)
            rule.ruleset = ruleset
            rule.save()
            messages.success(request, f'Rule created successfully!')
            return redirect('rules:ruleset_detail', pk=ruleset.pk)
    else:
        form = WAFRuleForm()
    
    return render(request, 'rules/rule_form.html', {
        'form': form,
        'ruleset': ruleset,
        'title': f'Add Rule to {ruleset.name}'
    })


@login_required
@staff_required
def rule_edit(request, pk):
    rule = get_object_or_404(WAFRule, pk=pk)
    
    if request.method == 'POST':
        form = WAFRuleForm(request.POST, instance=rule)
        if form.is_valid():
            rule = form.save()
            messages.success(request, f'Rule updated successfully!')
            return redirect('rules:ruleset_detail', pk=rule.ruleset.pk)
    else:
        form = WAFRuleForm(instance=rule)
    
    return render(request, 'rules/rule_form.html', {
        'form': form,
        'rule': rule,
        'ruleset': rule.ruleset,
        'title': f'Edit Rule in {rule.ruleset.name}'
    })


@login_required
@staff_required
def rule_delete(request, pk):
    rule = get_object_or_404(WAFRule, pk=pk)
    ruleset = rule.ruleset
    
    if request.method == 'POST':
        rule.delete()
        messages.success(request, 'Rule deleted successfully!')
        return redirect('rules:ruleset_detail', pk=ruleset.pk)
    
    return render(request, 'rules/rule_confirm_delete.html', {'rule': rule})


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
