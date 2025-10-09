from django import forms
from .models import WAFRule
from django import forms
from .models import RuleSet
from .models import WAFRule

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
        fields = ['rule_type', 'value', 'description', 'severity', 'is_active']
        widgets = {
            'rule_type': forms.Select(attrs={'class': 'form-select'}),
            'value': forms.Textarea(attrs={
                'class': 'form-textarea', 
                'rows': 4,
                'placeholder': 'Enter one pattern per line'
            }),
            'description': forms.TextInput(attrs={'class': 'form-input'}),
            'severity': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }
        help_texts = {
            'value': 'Patterns to match (one per line). Use regex for complex patterns.',
            'severity': 'How critical is this rule violation',
        }




class WAFRuleForm(forms.ModelForm):
    class Meta:
        model = WAFRule
        fields = "__all__"
