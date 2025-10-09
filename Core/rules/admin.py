from django.contrib import admin
from .models import WAFRule,RuleSet

admin.site.register(WAFRule)
admin.site.register(RuleSet)