from django import forms
from .models import Client

class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ["name", "host", "target_url"]
        widgets = {
            "host": forms.TextInput(attrs={"placeholder": "e.g., my-client.com"}),
            "target_url": forms.URLInput(attrs={"placeholder": "https://origin.example.com"}),
        }
