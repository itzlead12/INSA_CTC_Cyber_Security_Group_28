from django.db import models
from django.utils import timezone
from customers.models import Client
from django.db import models 
from django.contrib.auth.models import User

class RuleSet(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    RULESET_TYPES = [
        ('basic', 'Basic Protection'),
        ('owasp', 'OWASP CRS'),
        ('custom', 'Custom Rules'),
        ('ecommerce', 'E-Commerce'),
        ('api', 'API Protection'),
    ]
    ruleset_type = models.CharField(max_length=20, choices=RULESET_TYPES, default='custom')
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = 'Rule Set'
        verbose_name_plural = 'Rule Sets'


class WAFRule(models.Model):
    RULE_TYPES = [
        ("sql_injection", "SQL Injection"),
        ("recaptcha", "reCAPTCHA Challenge"),
        ("xss", "XSS"),
        ("rate_limit", "Rate Limiting"),
        ("ua_block", "User-Agent Blocking"),
        ("path_traversal", "Path Traversal"),
        ("rce", "Remote Code Execution"),
        ("lfi", "Local File Inclusion"),
        ("rfi", "Remote File Inclusion"),
    ]
    
    ruleset = models.ForeignKey(RuleSet, on_delete=models.CASCADE, related_name='rules')
    rule_type = models.CharField(max_length=50, choices=RULE_TYPES)
    value = models.TextField(help_text="One pattern per line for regex rules")
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=[
        ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')
    ], default='medium')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.ruleset.name} - {self.rule_type}"
    
    class Meta:
        verbose_name = 'WAF Rule'
        verbose_name_plural = 'WAF Rules'



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
