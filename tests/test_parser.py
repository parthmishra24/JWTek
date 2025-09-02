import base64
import json
from jwtek.core import parser
from datetime import datetime


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


def test_pretty_print_jwt_formats_timestamps(capsys):
    header = {}
    ts = 0
    payload = {"iat": ts, "exp": ts + 10, "nbf": ts}
    parser.pretty_print_jwt(header, payload, "sig")
    out = capsys.readouterr().out
    human = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    assert human in out
