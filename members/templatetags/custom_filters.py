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

@register.filter
def mask_email(email):
    """
    Mask an email, keeping first 4 characters before @
    and replacing the rest of the local part with 'x's.
    Example: smithjohnson@gmail.com -> smitxxxxxxxx@gmail.com
    """
    if not email or '@' not in email:
        return email
    local, domain = email.split('@', 1)
    return f"{local[:4]}{'x' * 8}@{domain}"

from django import template

register = template.Library()

@register.filter
def split(value, arg):
    return value.split(arg)