from django import forms
from .models import WAFRule
from django import forms
from .models import RuleSet

class RuleSetForm(forms.ModelForm):
    class Meta:
        model = RuleSet
        fields = ['name', 'description', 'ruleset_type', 'is_public', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input'}),
            'description': forms.Textarea(attrs={'class': 'form-textarea', 'rows': 3}),
            'ruleset_type': forms.Select(attrs={'class': 'form-select'}),
            'is_public': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }
        help_texts = {
            'is_public': 'Make this rule set available to all clients',
            'ruleset_type': 'Category for organizing rule sets',
        }





class WAFRuleForm(forms.ModelForm):
    class Meta:
        model = WAFRule
        fields = "__all__"
