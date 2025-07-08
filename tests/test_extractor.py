import base64
import json
import sys

# Provide a dummy 'requests' module so extractor can be imported without the
# real dependency installed.
sys.modules.setdefault("requests", type("Dummy", (), {})())

from jwtek.core import extractor


def forge_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    # Add a dummy signature so it matches extractor's JWT regex
    return f"{header_b64}.{payload_b64}.sig"


def test_extract_jwt_from_text_found():
    token = forge_none({"id": 1})
    text = f"Authorization: Bearer {token}"
    assert extractor.extract_jwt_from_text(text) == token


def test_extract_jwt_from_text_none():
    assert extractor.extract_jwt_from_text("no token here") is None
