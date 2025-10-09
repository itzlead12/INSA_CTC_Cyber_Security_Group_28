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



