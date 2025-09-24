from django.db import models
from django.db import models
from django.utils import timezone
from customers.models import Client

class WAFRule(models.Model):
    RULE_TYPES = [
        ("sql_injection", "SQL Injection"),
        ("xss", "Cross-Site Scripting"),
        ("rate_limit", "Rate Limiting"),
        ("geo_block", "Geo Block"),
        ("ua_block", "User-Agent Block"),
    ]
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="rules")
    rule_type = models.CharField(max_length=50, choices=RULE_TYPES)
    value = models.CharField(max_length=255, blank=True, help_text="Rule value. For geo_block, comma-separated country codes; for rate_limit, format 'requests/seconds'; for ua_block, substring match.")
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.client.name}: {self.rule_type}={self.value} ({'on' if self.is_active else 'off'})"

class BlockedRequest(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="blocked_requests")
    ip_address = models.GenericIPAddressField()
    request_path = models.TextField()
    user_agent = models.TextField(blank=True)
    reason = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"[{self.timestamp}] {self.client.name} {self.ip_address} {self.reason}"
