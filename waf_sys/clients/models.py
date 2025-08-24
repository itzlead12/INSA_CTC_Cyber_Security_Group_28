from django.db import models
from django.contrib.auth.models import User

class Client(models.Model):
    name = models.CharField(max_length=255, unique=True)
    host = models.CharField(max_length=255, unique=True, help_text="The client's domain (e.g., example.com)", default="example.com")
    target_url = models.URLField(help_text="The origin server (e.g., https://webserver.internal)")

    def __str__(self):
        return self.name

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    client = models.ForeignKey(Client, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} -> {self.client}"
