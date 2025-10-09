from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib import messages
from django.http import JsonResponse
from django.db import IntegrityError, models
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from django.views.generic import CreateView, UpdateView, ListView, DetailView
from django.urls import reverse_lazy
from django.utils import timezone
from .models import Client, ClientRuleSet
from .forms import ClientForm, ClientRegistrationForm, ClientOnboardingForm
from rules.models import RuleSet, WAFRule, RuleSet
from django.views.decorators.csrf import csrf_exempt
from logs.models import RequestLog
import json,pytz
from django.db.models import Count, Q, Case, When, Sum, IntegerField, Value

from datetime import datetime, timedelta

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)

def is_valid_ip_or_cidr(ip_str):
    """Validate IP address or CIDR notation"""
    if '/' in ip_str:
        ip_part, prefix = ip_str.split('/', 1)
        try:
            validate_ipv46_address(ip_part)
            prefix = int(prefix)
            return 0 <= prefix <= 128
        except (ValueError, ValidationError):
            return False
    else:
        try:
            validate_ipv46_address(ip_str)
            return True
        except ValidationError:
            return False



@login_required
def client_register(request):
    
    user_clients = Client.objects.filter(owner=request.user)
    if user_clients.exists():
        # If user already has clients, redirect to dashboard
        return redirect('clients:client_dashboard_first')
    
    if request.method == 'POST':
        form = ClientRegistrationForm(request.POST)
        if form.is_valid():
            try:
                client = form.save(commit=False)
                client.owner = request.user
                
                # Save enhanced site information
                client.site_description = form.cleaned_data.get('site_description', '')
                client.site_type = form.cleaned_data.get('site_type', 'other')
                client.expected_traffic = form.cleaned_data.get('expected_traffic', 'medium')
                client.save()
                
                
                basic_ruleset = RuleSet.objects.filter(is_public=True, ruleset_type='basic').first()
                if basic_ruleset:
                    ClientRuleSet.objects.create(client=client, ruleset=basic_ruleset)
                
                messages.success(request, f'Website "{client.name}" registered successfully!')
                return redirect('clients:client_onboarding', pk=client.pk)
                
            except IntegrityError as e:
                if 'name' in str(e):
                    form.add_error('name', 'A client with this name already exists.')
                elif 'host' in str(e):
                    form.add_error('host', 'A client with this host already exists.')
    else:
        form = ClientRegistrationForm()
    
    return render(request, 'clients/client_register.html', {
        'form': form,
        'step': 1,
        'total_steps': 3
    })


def client_dashboard_first(request):
    """Redirect to first client's dashboard or registration"""
    if not request.user.is_authenticated:
        return redirect('dashboard:login')
    
    user_clients = Client.objects.filter(owner=request.user)
    
    if user_clients.exists():
        
        first_client = user_clients.first()
        return redirect('clients:client_dashboard', pk=first_client.pk)
    else:
        
        return redirect('clients:client_register')
    
@login_required
def client_onboarding(request, pk):
    
    client = get_object_or_404(Client, pk=pk, owner=request.user)
    
    if request.method == 'POST':
        form = ClientOnboardingForm(request.POST, client=client)
        if form.is_valid():
            selected_rulesets = form.cleaned_data['rulesets']
            security_level = form.cleaned_data['security_level']
            enable_ssl = form.cleaned_data['enable_ssl']
            enable_rate_limiting = form.cleaned_data['enable_rate_limiting']
            
            
            client.security_level = security_level
            client.enable_ssl = enable_ssl
            client.enable_rate_limiting = enable_rate_limiting
            client.is_onboarded = True
            client.save()
            
            
            for ruleset in selected_rulesets:
                ClientRuleSet.objects.get_or_create(client=client, ruleset=ruleset)
            
            messages.success(request, 'Security configuration applied successfully!')
            return redirect('clients:client_dashboard', pk=client.pk)
    else:
        
        initial_rulesets = client.get_recommended_rulesets()
        form = ClientOnboardingForm(client=client, initial={
            'rulesets': initial_rulesets
        })
    
    return render(request, 'clients/client_onboarding.html', {
        'client': client,
        'form': form,
        'step': 2,
        'total_steps': 3,
        'recommended_rulesets': client.get_recommended_rulesets()
    })

@login_required
def client_dashboard(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    
    if not request.user.is_staff and client.owner != request.user:
        messages.error(request, "You don't have permission to view this client.")
        return redirect('dashboard:admin_dashboard')
    
    
    tz = pytz.timezone('UTC')
    now = datetime.now(tz)
    
   
    client_requests = RequestLog.objects.filter(client=client)
    total_blocked = client_requests.filter(blocked=True).count()
    total_allowed = client_requests.filter(blocked=False).count()
    
    
    yesterday = now - timedelta(days=1)
    recent_blocked = client_requests.filter(blocked=True, timestamp__gte=yesterday).count()
    recent_allowed = client_requests.filter(blocked=False, timestamp__gte=yesterday).count()
    
   
    active_rulesets = ClientRuleSet.objects.filter(client=client, is_active=True).select_related('ruleset')
    total_rules = 0
    
    for client_ruleset in active_rulesets:
        
        rules_count = WAFRule.objects.filter(
            ruleset=client_ruleset.ruleset, 
            is_active=True
        ).count()
        total_rules += rules_count
    
    recent_threats = client_requests.filter(blocked=True).select_related('client').order_by('-timestamp')[:10]
    
    waf_config = client.get_waf_configuration()
    
    context = {
        'client': client,
        'total_blocked': total_blocked,
        'total_allowed': total_allowed,
        'recent_blocked': recent_blocked,
        'recent_allowed': recent_allowed,
        'active_rulesets': active_rulesets,
        'total_rules': total_rules,
        'recent_threats': recent_threats,
        'waf_config': waf_config,
        'step': 3,
        'total_steps': 3,
        'onboarding_complete': client.is_onboarded,
    }
    return render(request, 'clients/client_dashboard.html', context)

@login_required
def client_analytics(request, pk):
 
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        messages.error(request, "Permission denied.")
        return redirect('dashboard:admin_dashboard')
    
   
    tz = pytz.timezone('UTC')
    now = datetime.now(tz)
    thirty_days_ago = now - timedelta(days=30)
    
    
    daily_traffic = []
    
    for i in range(30):
        day = now - timedelta(days=(29 - i))  
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        
        day_requests = RequestLog.objects.filter(
            client=client,
            timestamp__gte=day_start,
            timestamp__lt=day_end
        )
        
        total = day_requests.count()
        blocked = day_requests.filter(blocked=True).count()
        allowed = day_requests.filter(blocked=False).count()
        
        daily_traffic.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'total': total,
            'blocked': blocked,
            'allowed': allowed
        })

    top_blocked_ips = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=thirty_days_ago
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    context = {
        'client': client,
        'daily_traffic': json.dumps(daily_traffic),  # Convert to JSON for JavaScript
        'top_blocked_ips': top_blocked_ips,
    }
    return render(request, 'clients/client_analytics.html', context)




@login_required
def client_geo_threats(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        messages.error(request, "Permission denied.")
        return redirect('dashboard:admin_dashboard')
    
   
    thirty_days_ago = timezone.now() - timedelta(days=30)
    total_threats = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=thirty_days_ago
    ).count()
    
    context = {
        'client': client,
        'total_threats': total_threats,
    }
    return render(request, 'clients/client_geo_threats.html', context)




@login_required
def client_api_geo_threats(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    
    threat_by_country = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=thirty_days_ago,
        geolocation__isnull=False
    ).select_related('geolocation').values(
        'geolocation__country',
        'geolocation__country_code',
        'geolocation__latitude',
        'geolocation__longitude'
    ).annotate(
        threat_count=Count('id')
    ).order_by('-threat_count')
    
    
    map_data = []
    total_threats = 0
    
    for country in threat_by_country:
        lat = country['geolocation__latitude']
        lng = country['geolocation__longitude']
        
        
        if lat is not None and lng is not None:
            threat_count = country['threat_count']
            total_threats += threat_count
            
            map_data.append({
                'country': country['geolocation__country'] or 'Unknown',
                'country_code': country['geolocation__country_code'] or 'XX',
                'lat': float(lat),
                'lng': float(lng),
                'threats': threat_count,
                'unique_ips': 1,  
                'radius': min(50, max(10, threat_count // 2))
            })
    
    
    top_threat_sources = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=thirty_days_ago
    ).select_related('geolocation').values(
        'ip_address',
        'geolocation__country',
        'geolocation__city',
        'geolocation__isp',
        'reason',
        'timestamp'
    ).annotate(
        count=Count('id')
    ).order_by('-count')[:20]
    
    
    threat_sources_list = []
    for source in top_threat_sources:
        threat_sources_list.append({
            'ip_address': source['ip_address'],
            'country': source['geolocation__country'],
            'city': source['geolocation__city'],
            'isp': source['geolocation__isp'],
            'reason': source['reason'],
            'count': source['count'],
            'last_seen': source['timestamp'].isoformat() if source['timestamp'] else None
        })
    
    return JsonResponse({
        'map_data': map_data,
        'top_threat_sources': threat_sources_list,
        'total_threats': total_threats,
        'countries_count': len(map_data)
    })








@login_required
def client_threats(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        messages.error(request, "Permission denied.")
        return redirect('dashboard:admin_dashboard')
    
    
    tz = pytz.timezone('UTC')
    now = datetime.now(tz)
    
    threats = RequestLog.objects.filter(client=client, blocked=True).select_related('client').order_by('-timestamp')
    
    
    total_threats = threats.count()
    today_threats = threats.filter(timestamp__date=now.date()).count()
    week_threats = threats.filter(timestamp__gte=now - timedelta(days=7)).count()
    
   
    threat_by_type = threats.values('reason').annotate(
        count=models.Count('id')
    ).order_by('-count')
    
    context = {
        'client': client,
        'threats': threats,
        'total_threats': total_threats,
        'today_threats': today_threats,
        'week_threats': week_threats,
        'threat_by_type': threat_by_type,
    }
    return render(request, 'clients/client_threats.html', context)



@csrf_exempt
def client_api_stats(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    secret = request.headers.get("X-Internal-Secret")
    
   
    if secret == "your-secret-key-123":
        pass  
    else:
        if not request.user.is_staff and client.owner != request.user:
            return JsonResponse({'error': 'Permission denied'}, status=403)
    
    tz = pytz.timezone('UTC')
    now = datetime.now(tz)
    yesterday = now - timedelta(hours=24)

    
    client_requests = RequestLog.objects.filter(client=client)
    total_blocked = client_requests.filter(blocked=True).count()
    total_allowed = client_requests.filter(blocked=False).count()
    total_requests = total_blocked + total_allowed
    
    
    recent_blocked = client_requests.filter(blocked=True, timestamp__gte=yesterday).count()
    recent_allowed = client_requests.filter(blocked=False, timestamp__gte=yesterday).count()

    
    active_client_ruleset_ids = ClientRuleSet.objects.filter(
        client_id=client.pk,
        is_active=True
    ).values_list('ruleset_id', flat=True)
    
    total_rules = WAFRule.objects.filter(
        ruleset_id__in=active_client_ruleset_ids,
        is_active=True
    ).count()

    
    requests_by_hour = []
    for hour in range(24):
       
        hour_time = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if hour > now.hour:
            hour_time = hour_time - timedelta(days=1)
        
        hour_start = hour_time
        hour_end = hour_time + timedelta(hours=1)
        
        
        blocked_count = RequestLog.objects.filter(
            client=client,
            timestamp__gte=hour_start,
            timestamp__lt=hour_end,
            blocked=True
        ).count()

        allowed_count = RequestLog.objects.filter(
            client=client,
            timestamp__gte=hour_start,
            timestamp__lt=hour_end,
            blocked=False
        ).count()

        
        requests_by_hour.append({
            "hour": hour,  
            "blocked": blocked_count,
            "allowed": allowed_count,
            "total": blocked_count + allowed_count
        })

    
    threat_types = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=yesterday
    ).values("reason").annotate(
        count=Count("id")
    ).order_by("-count")

    
    recent_activity = []
    recent_requests = client_requests.select_related('client').order_by('-timestamp')[:10]
    for request in recent_requests:
        recent_activity.append({
            "client_ip": request.ip_address,
            "client_name": client.name,
            "path": request.request_path,
            "method": request.method,
            "user_agent": request.user_agent,
            "waf_blocked": request.blocked,
            "threat_type": request.reason if request.blocked else "allowed",
            "timestamp": request.timestamp.isoformat(),
        })

    return JsonResponse({
        "global_stats": {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "total_allowed": total_allowed,
            "total_clients": 1,
            "total_rules": total_rules,
            "recent_threats": recent_blocked,
            "requests_per_second": 0,
        },
        "charts_data": {
            "traffic_data": requests_by_hour,  
            "threat_data": {
                "labels": [t['reason'] for t in threat_types],
                "series": [t['count'] for t in threat_types]
            },
            "top_ips": []
        },
        "recent_activity": recent_activity,
        "timestamp": now.isoformat(),
    })

@login_required
def client_api_threats(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    
    week_ago = datetime.now() - timedelta(days=7)
    
    threats_by_type = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=week_ago
    ).values('reason').annotate(
        count=models.Count('id')
    ).order_by('-count')
   
    threat_timeline = []
    for i in range(7):
        day = datetime.now() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        day_threats = RequestLog.objects.filter(
            client=client,
            blocked=True,
            timestamp__gte=day_start,
            timestamp__lt=day_end
        ).count()
        
        threat_timeline.append({
            'date': day_start.date().isoformat(),
            'threats': day_threats
        })
    
    threat_timeline.reverse()
    
    return JsonResponse({
        'threats_by_type': list(threats_by_type),
        'threat_timeline': threat_timeline
    })

@login_required
def client_api_traffic(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    
    sixty_min_ago = datetime.now() - timedelta(minutes=60)
    
    
    traffic_by_minute = []
    for i in range(60):
        minute_start = sixty_min_ago + timedelta(minutes=i)
        minute_end = minute_start + timedelta(minutes=1)
        
        minute_data = RequestLog.objects.filter(
            client=client,
            timestamp__gte=minute_start,
            timestamp__lt=minute_end
        ).aggregate(
            total=models.Count('id'),
            blocked=models.Count('id', filter=models.Q(blocked=True))
        )
        
        traffic_by_minute.append({
            'minute': minute_start.strftime('%H:%M'),
            'total': minute_data['total'] or 0,
            'blocked': minute_data['blocked'] or 0
        })
    
    
    current_stats = {
        'total_requests_24h': RequestLog.objects.filter(
            client=client,
            timestamp__gte=datetime.now() - timedelta(hours=24)
        ).count(),
        'blocked_requests_24h': RequestLog.objects.filter(
            client=client,
            blocked=True,
            timestamp__gte=datetime.now() - timedelta(hours=24)
        ).count(),
        'block_rate_24h': 0
    }
    
    if current_stats['total_requests_24h'] > 0:
        current_stats['block_rate_24h'] = round(
            (current_stats['blocked_requests_24h'] / current_stats['total_requests_24h']) * 100, 2
        )
    
    return JsonResponse({
        'traffic_by_minute': traffic_by_minute,
        'current_stats': current_stats
    })

@login_required
@staff_required
def client_list(request):
    
    tz = pytz.timezone('UTC')
    now = datetime.now(tz)
    
    clients = Client.objects.all().order_by('-created_at')
    
    
    active_clients = clients.filter(is_active=True).count()
    total_clients = clients.count()
    
    
    recent_requests = RequestLog.objects.select_related('client').order_by('-timestamp')[:10]
    
    
    yesterday = now - timedelta(hours=24)
    top_threat_clients = Client.objects.filter(
        request_logs__blocked=True,  
        request_logs__timestamp__gte=yesterday
    ).annotate(
        threat_count=models.Count('request_logs') 
    ).order_by('-threat_count')[:5]
    
    context = {
        'clients': clients,
        'active_clients': active_clients,
        'total_clients': total_clients,
        'recent_requests': recent_requests,
        'top_threat_clients': top_threat_clients,
    }
    return render(request, 'clients/clients_list.html', context)

"""
@login_required
@staff_required
def client_create(request):
    
    if request.method == 'POST':
        form = ClientForm(request.POST)
        if form.is_valid():
            try:
                client = form.save()
                messages.success(request, f'Client "{client.name}" created successfully!')
                return redirect('clients:client_list')
            except IntegrityError as e:
                if 'name' in str(e):
                    form.add_error('name', 'A client with this name already exists.')
                elif 'host' in str(e):
                    form.add_error('host', 'A client with this host already exists.')
    else:
        form = ClientForm()
    
    return render(request, 'clients/client_form.html', {
        'form': form, 
        'action': 'Create',
        'title': 'Create New Client'
    })
"""


@login_required
@staff_required
def client_edit(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if request.method == 'POST':
        form = ClientRegistrationForm(request.POST, instance=client)
        if form.is_valid():
            try:
               
                client = form.save(commit=False)
                
                
                client.site_description = form.cleaned_data.get('site_description', '')
                client.site_type = form.cleaned_data.get('site_type', 'other')
                client.expected_traffic = form.cleaned_data.get('expected_traffic', 'medium')
                client.save()
                
                messages.success(request, f'Client "{client.name}" updated successfully!')
                return redirect('clients:client_list')
                
            except IntegrityError as e:
                if 'name' in str(e):
                    form.add_error('name', 'A client with this name already exists.')
                elif 'host' in str(e):
                    form.add_error('host', 'A client with this host already exists.')
        else:
            
            messages.error(request, 'Please correct the errors below.')
    else:
        
        initial_data = {
            'site_description': client.site_description,
            'site_type': client.site_type,
            'expected_traffic': client.expected_traffic,
        }
        form = ClientRegistrationForm(instance=client, initial=initial_data)
    
    return render(request, 'clients/client_form.html', {
        'form': form,
        'client': client,
        'title': f'Edit Client: {client.name}'
    })

@login_required
@staff_required
def client_delete(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if request.method == 'POST':
        
        confirm_text = request.POST.get('confirm_text', '')
        expected_text = f'DELETE {client.name}'
        
        if confirm_text != expected_text:
            messages.error(request, 'Confirmation text did not match. Please type exactly as shown.')
            return render(request, 'clients/client_confirm_delete.html', {'client': client})
        
        client_name = client.name
        client.delete()
        messages.success(request, f'Client "{client_name}" deleted successfully!')
        return redirect('clients:client_list')
    
    return render(request, 'clients/client_confirm_delete.html', {'client': client})


class ClientDetailView(LoginRequiredMixin, UserPassesTestMixin, DetailView):
    
    model = Client
    template_name = 'clients/client_detail.html'
    context_object_name = 'client'
    
    def test_func(self):
        client = self.get_object()
        return self.request.user.is_staff or client.owner == self.request.user
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        client = self.get_object()
        
        
        client_requests = RequestLog.objects.filter(client=client)
        context.update({
            'total_requests': client_requests.count(),
            'blocked_requests': client_requests.filter(blocked=True).count(),
            'active_rulesets': ClientRuleSet.objects.filter(client=client, is_active=True),
            'recent_activity': client_requests.order_by('-timestamp')[:20],
        })
        
        return context
    








#========================================

@login_required
def client_waf_config(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    waf_config = client.get_waf_configuration()
    return JsonResponse(waf_config)









@login_required
def client_blocking_management(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        messages.error(request, "Permission denied.")
        return redirect('dashboard:admin_dashboard')
    
  
    thirty_days_ago = timezone.now() - timedelta(days=30)
    

    blocked_by_country = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=thirty_days_ago,
        country_code__isnull=False
    ).exclude(country_code='').values('country_code').annotate(  # ← Keep this
        count=Count('id')
    ).order_by('-count')

    
    top_blocked_ips = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=thirty_days_ago
    ).values('ip_address', 'country_code', 'reason').annotate(
        count=Count('id')
    ).order_by('-count')[:20]
    
    
    country_data = []
    for country in blocked_by_country:
        country_data.append({
            'country_code': country['country_code'],
            'blocked_requests': country['count']
        })
    
    
    COUNTRIES = [
        ('US', 'United States'),
        ('CN', 'China'),
        ('RU', 'Russia'),
        ('BR', 'Brazil'),
        ('IN', 'India'),
        ('ET', 'Ethiopia'),
        ('GB', 'United Kingdom'),
        ('DE', 'Germany'),
        ('FR', 'France'),
        ('JP', 'Japan'),
        ('KR', 'South Korea'),
        ('CA', 'Canada'),
        ('AU', 'Australia'),
        ('MX', 'Mexico'),
        ('ZA', 'South Africa'),
        ('NG', 'Nigeria'),
        ('EG', 'Egypt'),
        ('SA', 'Saudi Arabia'),
        ('TR', 'Turkey'),
    ]
    COUNTRY_COORDS = {
    'US': {'name': 'United States', 'lat': 37.0902, 'lng': -95.7129},
    'CN': {'name': 'China', 'lat': 35.8617, 'lng': 104.1954},
    'RU': {'name': 'Russia', 'lat': 61.5240, 'lng': 105.3188},
    'ET': {'name': 'Ethiopia', 'lat': 9.1450, 'lng': 40.4897},
    'GB': {'name': 'United Kingdom', 'lat': 55.3781, 'lng': -3.4360},
    'DE': {'name': 'Germany', 'lat': 51.1657, 'lng': 10.4515},
    'FR': {'name': 'France', 'lat': 46.2276, 'lng': 2.2137},
    'JP': {'name': 'Japan', 'lat': 36.2048, 'lng': 138.2529},
    'IN': {'name': 'India', 'lat': 20.5937, 'lng': 78.9629},
    'BR': {'name': 'Brazil', 'lat': -14.2350, 'lng': -51.9253},
    'CA': {'name': 'Canada', 'lat': 56.1304, 'lng': -106.3468},
    'AU': {'name': 'Australia', 'lat': -25.2744, 'lng': 133.7751},
    'MX': {'name': 'Mexico', 'lat': 23.6345, 'lng': -102.5528},
    'ZA': {'name': 'South Africa', 'lat': -30.5595, 'lng': 22.9375},
    'NG': {'name': 'Nigeria', 'lat': 9.0820, 'lng': 8.6753},
    'EG': {'name': 'Egypt', 'lat': 26.8206, 'lng': 30.8025},
    'SA': {'name': 'Saudi Arabia', 'lat': 23.8859, 'lng': 45.0792},
    'TR': {'name': 'Turkey', 'lat': 38.9637, 'lng': 35.2433},
}
    
    context = {
    'client': client,
    'country_data': json.dumps(country_data),
    'top_blocked_ips': top_blocked_ips,
    'blocked_countries_count': blocked_by_country.count(),
    'total_blocked_requests': sum(item['count'] for item in blocked_by_country),
    'COUNTRIES': [(code, info['name']) for code, info in COUNTRY_COORDS.items()],  # For dropdown
    'COUNTRY_COORDS': json.dumps(COUNTRY_COORDS),  # For map
    }
    
    return render(request, 'clients/blocking_management.html', context)



@login_required
def update_blocking_settings(request, pk):
    client = get_object_or_404(Client, pk=pk)
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
           
            ip_blacklist = data.get('ip_blacklist', [])
            valid_ips = []
            for ip in ip_blacklist:
                ip = ip.strip()
                if ip and is_valid_ip_or_cidr(ip):
                    valid_ips.append(ip)
               
            
            client.enable_country_blocking = data.get('enable_country_blocking', False)
            client.blocked_countries = data.get('blocked_countries', [])
            client.allowed_countries = data.get('allowed_countries', [])
            client.enable_ip_blacklist = data.get('enable_ip_blacklist', False)
            client.ip_blacklist = valid_ips 
            
            client.save()
            
            return JsonResponse({'success': True, 'message': 'Blocking settings updated successfully'})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
def get_blocking_statistics(request, pk):
   
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    
    seven_days_ago = timezone.now() - timedelta(days=7)
    
    daily_stats = []
    for i in range(7):
        day = timezone.now() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        day_blocked = RequestLog.objects.filter(
            client=client,
            blocked=True,
            timestamp__gte=day_start,
            timestamp__lt=day_end
        ).count()
        
        daily_stats.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'blocked_requests': day_blocked
        })
    
    daily_stats.reverse()
    
    
    blocking_reasons = RequestLog.objects.filter(
        client=client,
        blocked=True,
        timestamp__gte=seven_days_ago
    ).values('reason').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    return JsonResponse({
        'daily_stats': daily_stats,
        'blocking_reasons': list(blocking_reasons),
        'total_blocked_week': sum(day['blocked_requests'] for day in daily_stats)
    })

@login_required
def quick_block_ip(request, pk):
    client = get_object_or_404(Client, pk=pk)
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            ip_address = data.get('ip_address', '').strip()
            
            if not ip_address:
                return JsonResponse({'success': False, 'error': 'IP address is required'})
            
            
            if not is_valid_ip_or_cidr(ip_address):
                return JsonResponse({'success': False, 'error': 'Invalid IP address or CIDR format'})
            
            if not client.enable_ip_blacklist:
                client.enable_ip_blacklist = True
            
            if ip_address not in client.ip_blacklist:
                client.ip_blacklist.append(ip_address)
                client.save()
                return JsonResponse({'success': True, 'message': f'IP {ip_address} added to blacklist'})
            else:
                return JsonResponse({'success': False, 'error': f'IP {ip_address} is already in blacklist'})
                
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@login_required
def remove_blocked_ip(request, pk):
    
    client = get_object_or_404(Client, pk=pk)
    
    if not request.user.is_staff and client.owner != request.user:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            ip_address = data.get('ip_address', '').strip()
            
            if ip_address in client.ip_blacklist:
                client.ip_blacklist.remove(ip_address)
                client.save()
                
                return JsonResponse({
                    'success': True,
                    'message': f'IP {ip_address} removed from blacklist'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': f'IP {ip_address} not found in blacklist'
                })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
