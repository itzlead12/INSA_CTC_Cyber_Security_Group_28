from django.contrib import admin
from .models import Client,ClientRuleSet

# Register your models here.
@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ['name', 'host', 'target_url', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'host']

admin.site.register(ClientRuleSet)
