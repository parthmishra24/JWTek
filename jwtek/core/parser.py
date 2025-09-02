import base64
import json
from datetime import datetime
from . import ui

def _b64_decode(data):
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _format_timestamps(payload):
    formatted = payload.copy()
    for claim in ("iat", "exp", "nbf"):
        if claim in formatted:
            try:
                formatted[claim] = datetime.fromtimestamp(int(formatted[claim])).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
    return formatted

def decode_jwt(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        header = json.loads(_b64_decode(header_b64))
        payload = json.loads(_b64_decode(payload_b64))
        return header, payload, signature_b64
    except Exception as e:
        ui.error(f"Failed to decode JWT: {e}")
        return {}, {}, ''

def pretty_print_jwt(header, payload, signature_b64):
    print("\n🧾 Decoded JWT Header:\n")
    print(json.dumps(header, indent=4))
    print("\n📦 Decoded JWT Payload:\n")
    print(json.dumps(_format_timestamps(payload), indent=4))
    print("\n🔏 Signature (base64):\n")
    print(signature_b64)
