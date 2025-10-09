import requests
from django.db import models
from django.utils import timezone
from .models import IPGeolocation

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
            # Skip private IPs
            if ip_address.startswith(('10.', '172.', '192.168.', '127.')):
                return self.create(ip_address=ip_address, country="Private Network")
            
            # Using ipapi.co (free tier available)
            response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=5)
            data = response.json()
            
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
            # Fallback: create basic entry
            return self.create(ip_address=ip_address)

# Add manager to IPGeolocation model
IPGeolocation.add_to_class('objects', IPGeolocationManager())