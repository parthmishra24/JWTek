import base64
import json

def _b64_decode(data):
    """Helper to decode base64url strings with padding handling."""
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def decode_jwt(token):
    """Split and decode a JWT."""
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        header = json.loads(_b64_decode(header_b64))
        payload = json.loads(_b64_decode(payload_b64))
        return header, payload, signature_b64
    except Exception as e:
        print(f"[!] Failed to decode JWT: {e}")
        return {}, {}, ''
