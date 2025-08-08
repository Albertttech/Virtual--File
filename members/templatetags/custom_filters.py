from django import template

register = template.Library()

@register.filter(name='replace')
def replace(value, arg):
    """
    Replaces all occurrences of 'old,new' in the string.
    Usage: {{ value|replace:"old,new" }}
    """
    old, new = arg.split(',', 1)
    return value.replace(old, new)
