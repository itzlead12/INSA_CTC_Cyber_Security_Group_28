from django.db import models
from django.contrib.auth.models import User
from django.urls import reverse
from rules.models import RuleSet, WAFRule

class Client(models.Model):
    name = models.CharField(max_length=255, unique=True)
    host = models.CharField(max_length=255, unique=True)
    target_url = models.URLField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='clients')
    
    
    site_description = models.TextField(blank=True)
    SITE_TYPE_CHOICES = [
        ('ecommerce', 'E-commerce Store'),
        ('blog', 'Blog/Content Website'),
        ('saas', 'SaaS Application'),
        ('api', 'API Service'),
        ('corporate', 'Corporate Website'),
        ('other', 'Other')
    ]
    site_type = models.CharField(max_length=20, choices=SITE_TYPE_CHOICES, default='other')
    
    TRAFFIC_CHOICES = [
        ('low', 'Low (under 1k visits/day)'),
        ('medium', 'Medium (1k-10k visits/day)'),
        ('high', 'High (10k-100k visits/day)'),
        ('enterprise', 'Enterprise (100k+ visits/day)')
    ]
    expected_traffic = models.CharField(max_length=20, choices=TRAFFIC_CHOICES, default='medium')
    
   
    security_level = models.CharField(max_length=20, choices=[
        ('basic', 'Basic Protection'),
        ('balanced', 'Balanced Protection'),
        ('strict', 'Strict Protection'),
        ('custom', 'Custom Configuration')
    ], default='balanced')
    
    enable_ssl = models.BooleanField(default=True)
    enable_rate_limiting = models.BooleanField(default=True)
    is_onboarded = models.BooleanField(default=False)
    enable_country_blocking = models.BooleanField(default=False)
    blocked_countries = models.JSONField(default=list, blank=True)  
    allowed_countries = models.JSONField(default=list, blank=True)
    enable_ip_blacklist = models.BooleanField(default=False)
    ip_blacklist = models.JSONField(default=list, blank=True)
    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        return reverse('clients:client_dashboard', kwargs={'pk': self.pk})
    
    def get_active_rulesets(self):
        """Get active ClientRuleSet objects for this client"""
        return self.rulesets.filter(is_active=True)
    
    def get_recommended_rulesets(self):
        """Get recommended rule sets based on site type"""
        if self.site_type == 'ecommerce':
            return RuleSet.objects.filter(ruleset_type__in=['basic', 'ecommerce', 'owasp'], is_active=True, is_public=True)
        elif self.site_type == 'api':
            return RuleSet.objects.filter(ruleset_type__in=['basic', 'api', 'owasp'], is_active=True, is_public=True)
        elif self.site_type == 'saas':
            return RuleSet.objects.filter(ruleset_type__in=['basic', 'owasp', 'api'], is_active=True, is_public=True)
        else:
            return RuleSet.objects.filter(ruleset_type__in=['basic', 'owasp'], is_active=True, is_public=True)
    
    def get_waf_configuration(self):
        """Generate WAF configuration for FastAPI"""
        client_rulesets = self.get_active_rulesets()
        rules = []
        
        for client_ruleset in client_rulesets:
            
            ruleset = client_ruleset.ruleset
            
            active_rules = WAFRule.objects.filter(
                ruleset=ruleset, 
                is_active=True
            ).values('rule_type', 'value', 'severity', 'description')
            
            rules.extend(list(active_rules))
        
        return {
        'id': self.pk,  
        'client_name': self.name,
        'client_host': self.host,
        'target_url': self.target_url,
        'security_level': self.security_level,
        'enable_ssl': self.enable_ssl,
        'enable_rate_limiting': self.enable_rate_limiting,
        'enable_country_blocking': self.enable_country_blocking,
        'blocked_countries': self.blocked_countries,
        'allowed_countries': self.allowed_countries,
        'enable_ip_blacklist': self.enable_ip_blacklist,
        'ip_blacklist': self.ip_blacklist,
        'rules': rules,
        'site_type': self.site_type,
        'expected_traffic': self.expected_traffic
    }
    
    class Meta:
        permissions = [
            ("view_client_dashboard", "Can view client dashboard"),
        ]
        ordering = ['-created_at']

class ClientRuleSet(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='rulesets')
    ruleset = models.ForeignKey(RuleSet, on_delete=models.CASCADE, related_name='client_rulesets')
    is_active = models.BooleanField(default=True)
    applied_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.client.name} - {self.ruleset.name} ({'Active' if self.is_active else 'Inactive'})"
    
    class Meta:
        unique_together = ['client', 'ruleset']
        verbose_name = 'Client Rule Set'
        verbose_name_plural = 'Client Rule Sets'
