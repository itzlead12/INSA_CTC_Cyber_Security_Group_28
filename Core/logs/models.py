# logs/models.py
from django.db import models
from clients.models import Client
import requests
from django.utils import timezone

class IPGeolocationManager(models.Manager):
    def get_or_fetch(self, ip_address):
        """Get existing geolocation or fetch new one"""
        try:
            return self.get(ip_address=ip_address)
        except IPGeolocation.DoesNotExist:
            return self.fetch_geolocation(ip_address)
    
    def fetch_geolocation(self, ip_address):
        """Fetch geolocation data from free API"""
        try:
            # Skip private IPs - but provide better default data
            if self._is_private_ip(ip_address):
                return self.create(
                    ip_address=ip_address, 
                    country="Private Network",
                    country_code="PRIV",
                    city="Local Network",
                    region="Internal",
                    latitude=0.0,
                    longitude=0.0,
                    isp="Internal Network"
                )
            
            # Using ipapi.co (free tier available)
            response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=5)
            data = response.json()
            
            # Check if we got valid data
            if data.get('error'):
                return self.create(ip_address=ip_address)
            
            return self.create(
                ip_address=ip_address,
                country=data.get('country_name', ''),
                country_code=data.get('country_code', ''),
                city=data.get('city', ''),
                region=data.get('region', ''),
                latitude=data.get('latitude'),
                longitude=data.get('longitude'),
                isp=data.get('org', '')
            )
        except Exception as e:
            # Fallback: create basic entry with better defaults
            print(f"Geolocation fetch failed for {ip_address}: {e}")
            return self.create(
                ip_address=ip_address,
                country="Unknown",
                country_code="XX",
                latitude=0.0,
                longitude=0.0
            )
    
    def _is_private_ip(self, ip_address):
        """Check if IP address is in private ranges"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', '0.',
            '169.254.', '::1', 'fc00:', 'fd00:', 'fe80:'
        ]
        return any(ip_address.startswith(prefix) for prefix in private_ranges)
    
class IPGeolocation(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    country = models.CharField(max_length=100, blank=True)
    country_code = models.CharField(max_length=2, blank=True)
    city = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    isp = models.CharField(max_length=200, blank=True)
    threat_level = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    ], default='low')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    
    # Use the custom manager
    objects = IPGeolocationManager()
    
    def __str__(self):
        return f"{self.ip_address} - {self.country}"
    
    class Meta:
        verbose_name = 'IP Geolocation'
        verbose_name_plural = 'IP Geolocations'

class RequestLog(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='request_logs')
    ip_address = models.GenericIPAddressField()
    request_path = models.TextField()
    user_agent = models.TextField(blank=True)
    method = models.CharField(max_length=10, default='GET')
    reason = models.TextField(blank=True)
    blocked = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    geolocation = models.ForeignKey(IPGeolocation, on_delete=models.SET_NULL, null=True, blank=True)
    country_code = models.CharField(max_length=5, blank=True)
    
    def __str__(self):
        status = "BLOCKED" if self.blocked else "ALLOWED"
        return f"{self.client.name} - {self.ip_address} - {status}"
    
    def save(self, *args, **kwargs):
    # Auto-populate geolocation data when saving
        if not self.geolocation:
            try:
                self.geolocation = IPGeolocation.objects.get_or_fetch(self.ip_address)
            except Exception as e:
                print(f"Error getting geolocation for {self.ip_address}: {e}")
    
    
        if self.geolocation and self.geolocation.country_code:
            self.country_code = self.geolocation.country_code
        else:
            self.country_code = ""  # Ensure it's not NULL
    
        super().save(*args, **kwargs)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['client', 'timestamp']),
            models.Index(fields=['blocked', 'timestamp']),
        ]