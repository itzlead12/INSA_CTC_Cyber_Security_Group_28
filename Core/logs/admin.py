from django.contrib import admin
from .models import RequestLog, IPGeolocation

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['client', 'ip_address', 'method', 'blocked', 'timestamp']
    list_filter = ['blocked', 'method', 'timestamp', 'client']
    search_fields = ['ip_address', 'request_path', 'reason']
    readonly_fields = ['timestamp']

admin.site.register(IPGeolocation)