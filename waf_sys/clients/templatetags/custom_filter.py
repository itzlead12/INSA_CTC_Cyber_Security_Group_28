from django import template

register = template.Library()

@register.filter
def get_range(value):
    return range(1, value + 1)


@register.filter
def div(value, arg):
    try:
        return float(value) / float(arg or 1)
    except:
        return 0

@register.filter
def mul(value, arg):
    return float(value) * float(arg)
