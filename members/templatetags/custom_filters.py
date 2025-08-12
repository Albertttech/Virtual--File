from django import template

register = template.Library()

@register.filter(name='mask_email')
def mask_email(email):
    """
    Mask an email address for display.
    Example: heavprograms@gmail.com → hea****@*****.com
    """
    if not email or '@' not in email:
        return email
    
    local_part, domain = email.split('@', 1)
    domain_parts = domain.split('.')
    
    # Show first 3 chars of local part
    masked_local = f"{local_part[:3]}****"
    
    # Mask domain except last part (like .com)
    masked_domain = f"*****.{domain_parts[-1]}" if len(domain_parts) > 1 else domain
    
    return f"{masked_local}@{masked_domain}"

@register.filter(name='split')
def split(value, arg):
    """Custom split filter that mimics Python's str.split()"""
    return value.split(arg)