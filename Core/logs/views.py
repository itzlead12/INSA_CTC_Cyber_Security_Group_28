from django.shortcuts import render,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q, Count
from .models import RequestLog,IPGeolocation
from clients.models import Client
from django.utils import timezone
from datetime import datetime, timedelta
import csv,json, logging
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

logger = logging.getLogger(__name__)

@login_required
def request_logs(request):
    """View for displaying request logs with filtering"""
    # Get filter parameters
    client_filter = request.GET.get('client', '')
    status_filter = request.GET.get('blocked', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    # Start with all logs
    logs = RequestLog.objects.select_related('client').all()
    
    # Apply filters
    if client_filter:
        logs = logs.filter(client_id=client_filter)
    
    if status_filter:
        if status_filter == 'true':
            logs = logs.filter(blocked=True)
        elif status_filter == 'false':
            logs = logs.filter(blocked=False)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            logs = logs.filter(timestamp__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            logs = logs.filter(timestamp__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Get statistics
    total_requests = RequestLog.objects.count()
    total_blocked = RequestLog.objects.filter(blocked=True).count()
    total_allowed = RequestLog.objects.filter(blocked=False).count()
    
    # Last 24 hours count
    last_24h = RequestLog.objects.filter(
        timestamp__gte=datetime.now() - timedelta(hours=24)
    ).count()

    
    # Pagination
    paginator = Paginator(logs.order_by('-timestamp'), 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all clients for filter dropdown
    clients = Client.objects.all()
    
    context = {
        'logs': page_obj,
        'total_requests': total_requests,
        'total_blocked': total_blocked,
        'total_allowed': total_allowed,
        'last_24h': last_24h,
        'clients': clients,
    }
    return render(request, 'logs/request_logs.html', context)

@login_required
def export_logs(request):
    """Export logs to CSV"""
    # Get filter parameters (same as request_logs view)
    client_filter = request.GET.get('client', '')
    status_filter = request.GET.get('blocked', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    logs = RequestLog.objects.select_related('client').all()
    
    # Apply filters
    if client_filter:
        logs = logs.filter(client_id=client_filter)
    if status_filter == 'true':
        logs = logs.filter(blocked=True)
    elif status_filter == 'false':
        logs = logs.filter(blocked=False)
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            logs = logs.filter(timestamp__date__gte=date_from_obj)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            logs = logs.filter(timestamp__date__lte=date_to_obj)
        except ValueError:
            pass
    
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="waf_logs.csv"'
    writer = csv.writer(response)
    
    writer.writerow(['Timestamp', 'Client', 'IP Address', 'Method', 'Path', 'Status', 'Reason', 'User Agent'])
    
    for log in logs.order_by('-timestamp'):
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.client.name,
            log.ip_address,
            log.method,
            log.request_path[:100],  # Limit path length
            'BLOCKED' if log.blocked else 'ALLOWED',
            log.reason,
            log.user_agent[:100]  # Limit user agent length
        ])
    
    return response

@login_required
def log_details_api(request, log_id):
    """API endpoint for log details"""
    try:
        log = RequestLog.objects.select_related('client').get(id=log_id)
        data = {
            'id': log.id,
            'client_name': log.client.name,
            'ip_address': log.ip_address,
            'request_path': log.request_path,
            'method': log.method,
            'user_agent': log.user_agent,
            'blocked': log.blocked,
            'reason': log.reason,
            'timestamp': log.timestamp.isoformat(),
        }
        return JsonResponse(data)
    except RequestLog.DoesNotExist:
        return JsonResponse({'error': 'Log not found'}, status=404)

def get_ip_geolocation(request, ip_address):
    """API endpoint to get geolocation data for an IP"""
    try:
        geolocation = IPGeolocation.objects.get_or_fetch(ip_address)
        return JsonResponse({
            'ip_address': geolocation.ip_address,
            'country': geolocation.country,
            'country_code': geolocation.country_code,
            'city': geolocation.city,
            'region': geolocation.region,
            'latitude': geolocation.latitude,
            'longitude': geolocation.longitude,
            'isp': geolocation.isp,
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def log_security_event(request):
    """
    Internal API endpoint for FastAPI WAF to log security events.
    No authentication required (internal service communication).
    """
    try:
        data = json.loads(request.body)

        # Validate required fields
        required_fields = ['client_host', 'ip_address', 'request_path', 'blocked']
        for field in required_fields:
            if field not in data:
                return JsonResponse({'error': f'Missing field: {field}'}, status=400)

        # Find client by host
        host_ip = data['client_host'].split(':')[0]  # remove port
        try:
            client = Client.objects.get(host=host_ip, is_active=True)
        except Client.DoesNotExist:
            logger.warning(f"Security event for unknown client host: {host_ip}")
            return JsonResponse({'error': 'Client not found'}, status=404)

        # Create log entry
        RequestLog.objects.create(
            client=client,
            ip_address=data['ip_address'],
            request_path=data['request_path'],
            user_agent=data.get('user_agent', ''),
            method=data.get('method', 'GET'),
            reason=data.get('reason', ''),
            blocked=data['blocked'],
        )

        return JsonResponse({'status': 'logged'}, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
        return JsonResponse({'error': 'Internal error'}, status=500)
    

@login_required
def threat_analysis(request):
    """Threat analysis dashboard"""
    # Last 30 days data
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    # Threat statistics
    threats = RequestLog.objects.filter(
        blocked=True,
        timestamp__gte=thirty_days_ago
    )
    
    # Threats by type
    threats_by_type = threats.values('reason').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Threats by client
    threats_by_client = threats.values('client__name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Daily threat trend
    daily_threats = []
    for i in range(30):
        day = datetime.now() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        day_count = threats.filter(
            timestamp__gte=day_start,
            timestamp__lt=day_end
        ).count()
        
        daily_threats.append({
            'date': day_start.date().isoformat(),
            'count': day_count
        })
    
    daily_threats.reverse()
    
    context = {
        'threats_by_type': threats_by_type,
        'threats_by_client': threats_by_client,
        'daily_threats': daily_threats,
        'total_threats_30d': threats.count(),
        'avg_daily_threats': threats.count() / 30,
    }
    return render(request, 'logs/threat_analysis.html', context)