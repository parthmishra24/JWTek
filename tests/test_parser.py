import base64
import json
from jwtek.core import parser


def forge_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    # Add a dummy signature so the token matches typical JWT structure
    return f"{header_b64}.{payload_b64}.sig"


def test_decode_jwt_valid():
    token = forge_none({"user": "john"})
    header, payload, signature = parser.decode_jwt(token)
    assert header == {"alg": "none", "typ": "JWT"}
    assert payload == {"user": "john"}
    assert signature == "sig"


def test_decode_jwt_invalid():
    header, payload, signature = parser.decode_jwt("invalid-token")
    assert header == {}
    assert payload == {}
    assert signature == ""
