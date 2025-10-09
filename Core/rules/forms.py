from django import forms
from .models import WAFRule

class WAFRuleForm(forms.ModelForm):
    class Meta:
        model = WAFRule
        fields = "__all__"
