from django import forms
from .models import Client, ClientRuleSet
from rules.models import RuleSet



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

class ClientRegistrationForm(forms.ModelForm):
    """Form for client registration by users - now also suitable for editing"""
    agree_terms = forms.BooleanField(
        required=False,
        error_messages={'required': 'You must agree to the terms and conditions'}
    )
    
    class Meta:
        model = Client
        fields = ['name', 'host', 'target_url', 'site_description', 'site_type', 'expected_traffic', 'agree_terms']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'My Web Application'
            }),
            'host': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'myapp.example.com'
            }),
            'target_url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': 'https://my-backend-server.com'
            }),
            'site_description': forms.Textarea(attrs={
                'class': 'form-textarea',
                'placeholder': 'Describe your website or application...',
                'rows': 3
            }),
            'site_type': forms.Select(attrs={'class': 'form-select'}),
            'expected_traffic': forms.Select(attrs={'class': 'form-select'}),
            'agree_terms': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }
        help_texts = {
            'host': 'The domain that will point to our WAF',
            'target_url': 'Your actual backend server URL',
            'site_description': 'Help us provide better protection by describing your site',
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        if self.instance and self.instance.pk:
            self.fields['agree_terms'].required = False
    
    def clean_host(self):
        host = self.cleaned_data['host'].lower().strip()
       
        host = host.replace('http://', '').replace('https://', '').split('/')[0]
        
       
        if self.instance and self.instance.pk:
            if Client.objects.filter(host=host).exclude(pk=self.instance.pk).exists():
                raise forms.ValidationError('This host is already registered')
        else:
            if Client.objects.filter(host=host).exists():
                raise forms.ValidationError('This host is already registered')
        return host
    
    def clean_name(self):
        name = self.cleaned_data['name']
        
        
        if self.instance and self.instance.pk:
            if Client.objects.filter(name=name).exclude(pk=self.instance.pk).exists():
                raise forms.ValidationError('A client with this name already exists')
        else:
            if Client.objects.filter(name=name).exists():
                raise forms.ValidationError('A client with this name already exists')
        return name
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        
        if 'site_description' in self.cleaned_data:
            instance.site_description = self.cleaned_data.get('site_description', '')
        if 'site_type' in self.cleaned_data:
            instance.site_type = self.cleaned_data.get('site_type', 'other')
        if 'expected_traffic' in self.cleaned_data:
            instance.expected_traffic = self.cleaned_data.get('expected_traffic', 'medium')
        
        if commit:
            instance.save()
        
        return instance


class ClientOnboardingForm(forms.Form):
    """Form for rule set selection during onboarding"""
    rulesets = forms.ModelMultipleChoiceField(
        queryset=RuleSet.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        help_text='Select one or more security rule sets for your application'
    )
    
    security_level = forms.ChoiceField(
        choices=[
            ('basic', 'Basic Protection (Recommended for starters)'),
            ('balanced', 'Balanced Protection (Recommended for most sites)'),
            ('strict', 'Strict Protection (For high-security needs)'),
            ('custom', 'Custom Configuration (Advanced users)')
        ],
        initial='balanced',
        widget=forms.RadioSelect,
        help_text='Select your desired security level'
    )
    
    enable_ssl = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput,
        help_text='Enable SSL/TLS termination (recommended)'
    )
    
    enable_rate_limiting = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput,
        help_text='Enable rate limiting protection'
    )
    
   
    enable_country_blocking = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput,
        help_text='Enable country-based access control'
    )
    
    blocked_countries = forms.MultipleChoiceField(
        choices=COUNTRIES,
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-select',
            'size': '6'
        }),
        help_text='Select countries to block (optional)'
    )
    
 
    enable_ip_blacklist = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput,
        help_text='Enable IP blacklisting'
    )
    
    ip_blacklist = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 3,
            'placeholder': '192.168.1.1\n10.0.0.0/24\n203.0.113.45'
        }),
        help_text='Enter one IP address or CIDR range per line (optional)'
    )
    
    def __init__(self, *args, **kwargs):
        self.client = kwargs.pop('client', None)
        super().__init__(*args, **kwargs)
        
       
        if self.client:
          
            assigned_ruleset_ids = ClientRuleSet.objects.filter(
                client=self.client
            ).values_list('ruleset_id', flat=True)
            
            self.fields['rulesets'].queryset = RuleSet.objects.filter(
                is_active=True, 
                is_public=True
            ).exclude(
                id__in=assigned_ruleset_ids 
            )
            
            
            if hasattr(self.client, 'site_type'):
                recommended_rulesets = self.client.get_recommended_rulesets()
                self.fields['rulesets'].initial = recommended_rulesets
            
            
            if self.client.pk:
                self.fields['blocked_countries'].initial = self.client.blocked_countries or []
                self.fields['ip_blacklist'].initial = '\n'.join(self.client.ip_blacklist or [])
    
    def clean_ip_blacklist(self):
        ip_blacklist_text = self.cleaned_data.get('ip_blacklist', '')
        if ip_blacklist_text:
            
            ip_list = [ip.strip() for ip in ip_blacklist_text.split('\n') if ip.strip()]
            
           
            import ipaddress
            valid_ips = []
            for ip in ip_list:
                try:
                    if '/' in ip:
                       
                        ipaddress.ip_network(ip, strict=False)
                    else:
                       
                        ipaddress.ip_address(ip)
                    valid_ips.append(ip)
                except ValueError:
                    raise forms.ValidationError(f"Invalid IP address or CIDR range: {ip}")
            
            return valid_ips
        return []

class ClientForm(forms.ModelForm):
    """Admin form for client management"""
    
    # NEW: Country blocking fields
    blocked_countries = forms.MultipleChoiceField(
        choices=COUNTRIES,
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-select',
            'size': '8'
        }),
        help_text="Select countries to block. Hold Ctrl/Cmd to select multiple."
    )
    
    allowed_countries = forms.MultipleChoiceField(
        choices=COUNTRIES,
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-select',
            'size': '8'
        }),
        help_text="Select countries to allow (allow-list mode). If set, only these countries can access."
    )
    
    # NEW: IP blacklisting fields
    ip_blacklist = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-textarea',
            'rows': 4,
            'placeholder': '192.168.1.1\n10.0.0.0/24\n203.0.113.45'
        }),
        help_text="Enter one IP address or CIDR range per line."
    )
    
    class Meta:
        model = Client
        fields = [
            'name', 'host', 'target_url', 'is_active', 'owner',
            'site_description', 'site_type', 'expected_traffic',
            'security_level', 'enable_ssl', 'enable_rate_limiting',
            'enable_country_blocking', 'blocked_countries', 'allowed_countries',
            'enable_ip_blacklist', 'ip_blacklist'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'host': forms.TextInput(attrs={'class': 'form-input'}),
            'target_url': forms.URLInput(attrs={'class': 'form-input'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'owner': forms.Select(attrs={'class': 'form-select'}),
            'site_description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 3}),
            'site_type': forms.Select(attrs={'class': 'form-select'}),
            'expected_traffic': forms.Select(attrs={'class': 'form-select'}),
            'security_level': forms.Select(attrs={'class': 'form-select'}),
            'enable_ssl': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'enable_rate_limiting': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'enable_country_blocking': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'enable_ip_blacklist': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
       
        from django.contrib.auth import get_user_model
        User = get_user_model()
        self.fields['owner'].queryset = User.objects.filter(is_active=True)
        
        if self.instance.pk:
            self.fields['blocked_countries'].initial = self.instance.blocked_countries or []
            self.fields['allowed_countries'].initial = self.instance.allowed_countries or []
            self.fields['ip_blacklist'].initial = '\n'.join(self.instance.ip_blacklist or [])
    
    def clean_ip_blacklist(self):
        ip_blacklist_text = self.cleaned_data.get('ip_blacklist', '')
        if ip_blacklist_text:
          
            ip_list = [ip.strip() for ip in ip_blacklist_text.split('\n') if ip.strip()]
            
           
            import ipaddress
            valid_ips = []
            for ip in ip_list:
                try:
                    if '/' in ip:
                     
                        ipaddress.ip_network(ip, strict=False)
                    else:
                        
                        ipaddress.ip_address(ip)
                    valid_ips.append(ip)
                except ValueError:
                    raise forms.ValidationError(f"Invalid IP address or CIDR range: {ip}")
            
            return valid_ips
        return []
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        
        
        ip_blacklist_text = self.cleaned_data.get('ip_blacklist', '')
        if ip_blacklist_text:
          
            ip_list = [ip.strip() for ip in ip_blacklist_text.split('\n') if ip.strip()]
            instance.ip_blacklist = ip_list
        else:
            instance.ip_blacklist = []
        
        if commit:
            instance.save()
        return instance

class ClientRuleSetForm(forms.ModelForm):
    """Form for assigning rule sets to clients"""
    class Meta:
        model = ClientRuleSet
        fields = ['ruleset', 'is_active']
        widgets = {
            'ruleset': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }
    
    def __init__(self, *args, **kwargs):
        client = kwargs.pop('client', None)
        super().__init__(*args, **kwargs)
        
        if client:
            
            existing_rulesets = ClientRuleSet.objects.filter(
                client=client
            ).values_list('ruleset_id', flat=True)
            
            self.fields['ruleset'].queryset = RuleSet.objects.exclude(
                id__in=existing_rulesets
            )
