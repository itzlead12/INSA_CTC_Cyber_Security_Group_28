from django.db import models
from django.contrib.auth.models import User

#model for the clients info
class Client(models.Model):
    name = models.CharField(max_length=255, unique=True)
    api_key = models.CharField(max_length=255, unique=True)
    target_url = models.URLField() 

    def __str__(self):
        return self.name
#model for the clients web owner
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    client = models.ForeignKey(Client, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} -> {self.client}"
