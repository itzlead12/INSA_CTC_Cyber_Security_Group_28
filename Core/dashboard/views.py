from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.http import JsonResponse
from logs.models import RequestLog
from django.views.decorators.csrf import csrf_exempt
from clients.models import Client
from rules.models import WAFRule
from django.db.models import Count, Q
from datetime import datetime, timedelta
import pytz

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)



def register(request):
    """User registration (sign up) page - NO login required"""
    if request.user.is_authenticated:
        return redirect('clients:client_register')
        
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            
            if user is not None:
                login(request, user)
                messages.success(request, 'Account created successfully! Please register your website.')
                return redirect('clients:client_register') 
    else:
        form = UserCreationForm()
    
    return render(request, 'dashboard/register.html', {'form': form})



def landing_page(request):
    return render(request, 'dashboard/landing.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:admin_dashboard')
        
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                next_url = request.GET.get('next', 'dashboard:admin_dashboard')
                return redirect(next_url)
    else:
        form = AuthenticationForm()
    return render(request, 'dashboard/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('dashboard:login')




@login_required
@staff_required
def admin_dashboard(request):
    
    context = {
        'total_blocked': 0,  
        'total_allowed': RequestLog.objects.filter(blocked=False).count,  
        'total_clients': Client.objects.count(),
        'total_rules': WAFRule.objects.filter(is_active=True).count(),
        'recent_requests': [],  
        'recent_threats': 0,  
    }
    return render(request, 'dashboard/admin_dashboard.html', context)


@csrf_exempt
def api_dashboard_stats(request):
    """API endpoint for global (admin-wide) dashboard statistics"""
    try:
        # Use timezone-aware datetime
        tz = pytz.timezone('UTC')
        now = datetime.now(tz)
        yesterday = now - timedelta(hours=24)
        
        print(f"📊 API called - Time range: {yesterday} to {now}")

        # Basic counts - test if database has data
        total_requests_count = RequestLog.objects.count()
        total_clients_count = Client.objects.count()
        total_rules_count = WAFRule.objects.filter(is_active=True).count()
        
        print(f"📈 Database counts - Requests: {total_requests_count}, Clients: {total_clients_count}, Rules: {total_rules_count}")

        # Statistics
        total_blocked = RequestLog.objects.filter(blocked=True).count()
        total_allowed = RequestLog.objects.filter(blocked=False).count()
        
        print(f"🛡️ Blocked: {total_blocked}, Allowed: {total_allowed}")

        # Recent activity (last 10 requests with client info)
        recent_requests = RequestLog.objects.select_related('client').order_by('-timestamp')[:10]
        print(f"📋 Recent requests found: {recent_requests.count()}")

        # Threat statistics (last 24 hours)
        recent_threats = RequestLog.objects.filter(
            blocked=True, 
            timestamp__gte=yesterday
        ).count()
        print(f" Recent threats (24h): {recent_threats}")

        # Additional data for charts - with better error handling
        requests_by_hour = []
        for hour in range(24):
            hour_start = yesterday.replace(hour=hour, minute=0, second=0, microsecond=0, tzinfo=tz)
            hour_end = hour_start + timedelta(hours=1)

            try:
                blocked_count = RequestLog.objects.filter(
                    timestamp__gte=hour_start,
                    timestamp__lt=hour_end,
                    blocked=True
                ).count()

                allowed_count = RequestLog.objects.filter(
                    timestamp__gte=hour_start,
                    timestamp__lt=hour_end,
                    blocked=False
                ).count()

                requests_by_hour.append({
                    "hour": hour,  # Use hour instead of x/y format
                    "blocked": blocked_count,
                    "allowed": allowed_count,
                    "total": blocked_count + allowed_count
                })
            except Exception as e:
                print(f" Error processing hour {hour}: {e}")
                requests_by_hour.append({
                    "hour": hour,
                    "blocked": 0,
                    "allowed": 0,
                    "total": 0
                })

        # Top blocked IPs
        try:
            top_blocked_ips = RequestLog.objects.filter(
                blocked=True,
                timestamp__gte=yesterday
            ).values("ip_address").annotate(
                count=Count("id")
            ).order_by("-count")[:10]
            print(f" Top blocked IPs: {len(top_blocked_ips)}")
        except Exception as e:
            print(f" Error getting top blocked IPs: {e}")
            top_blocked_ips = []

        # Threat type distribution
        try:
            threat_types = RequestLog.objects.filter(
                blocked=True,
                timestamp__gte=yesterday
            ).values("reason").annotate(
                count=Count("id")
            ).order_by("-count")
            print(f" Threat types: {len(threat_types)}")
        except Exception as e:
            print(f" Error getting threat types: {e}")
            threat_types = []

        # Prepare recent activity data for API response
        recent_activity_data = []
        for request in recent_requests:
            recent_activity_data.append({
                "id": request.id,
                "client_name": request.client.name if request.client else "Unknown",
                "client_id": request.client.id if request.client else None,
                "ip_address": request.ip_address,
                "request_path": request.request_path,
                "method": request.method,
                "user_agent": request.user_agent,
                "blocked": request.blocked,
                "reason": request.reason or "No reason provided",
                "timestamp": request.timestamp.isoformat() if request.timestamp else now.isoformat(),
                
            })

        print(f" API response prepared with {len(recent_activity_data)} recent activities")

        response_data = {
            # Global statistics
            "global_stats": {
                "total_requests": total_requests_count,
                "total_blocked": total_blocked,
                "total_allowed": total_allowed,
                "total_clients": total_clients_count,
                "total_rules": total_rules_count,
                "recent_threats": recent_threats,
                "requests_per_second": 0,
            },
            
            # Chart data
            "charts_data": {
                "requests_by_hour": requests_by_hour,
                "threat_types": list(threat_types),
                "top_blocked_ips": list(top_blocked_ips),
            },
            
            # Recent activity
            "recent_activity": recent_activity_data,
            
            # Debug info
            "debug": {
                "database_has_data": total_requests_count > 0,
                "time_range": {
                    "start": yesterday.isoformat(),
                    "end": now.isoformat()
                },
                "timestamp": now.isoformat()
            }
        }
        
        return JsonResponse(response_data)
    
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f" Critical error in api_dashboard_stats: {e}")
        print(f" Traceback: {error_traceback}")
        
        # Return basic fallback data with error info
        return JsonResponse({
            "global_stats": {
                "total_requests": 0,
                "total_blocked": 0,
                "total_allowed": 0,
                "total_clients": 0,
                "total_rules": 0,
                "recent_threats": 0,
                "requests_per_second": 0,
            },
            "charts_data": {
                "requests_by_hour": [],
                "threat_types": [],
                "top_blocked_ips": [],
            },
            "recent_activity": [],
            "error": str(e),
            "debug": {
                "database_has_data": False,
                "error_occurred": True
            }
        })
