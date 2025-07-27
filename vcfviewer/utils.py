import quopri
import base64

def decode_vcard_text(value, encoding=None):
    if encoding == 'QUOTED-PRINTABLE':
        return quopri.decodestring(value).decode('utf-8', errors='ignore')
    elif encoding == 'BASE64' or encoding == 'B':
        return base64.b64decode(value).decode('utf-8', errors='ignore')
    return value

def parse_name(vcard):
    # Use FN field if available
    if 'fn' in vcard.contents:
        return vcard.contents['fn'][0].value

    # If FN is missing, fallback to N (name parts)
    if 'n' in vcard.contents:
        n_field = vcard.contents['n'][0].value  # vobject.vcard.Name object
        parts = [n_field.prefix, n_field.given, n_field.additional, n_field.family, n_field.suffix]
        return " ".join(part for part in parts if part) or "Unknown"

    return "Unknown"
