import base64
import json
import sys
import types
from unittest import mock

# Provide dummy termcolor to avoid dependency
sys.modules.setdefault("termcolor", type("Dummy", (), {"cprint": lambda *a, **k: None})())

# Setup a simple jwt module used by forge
class _DummyException(Exception):
    pass

jwt_mod = sys.modules.setdefault("jwt", types.ModuleType("jwt"))
exc_mod = sys.modules.setdefault("jwt.exceptions", types.ModuleType("jwt.exceptions"))
exc_mod.InvalidSignatureError = _DummyException
exc_mod.DecodeError = _DummyException
jwt_mod.InvalidSignatureError = _DummyException
jwt_mod.exceptions = exc_mod


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def encode(payload, secret, algorithm=None, headers=None):
    header_json = json.dumps(headers or {})
    payload_json = json.dumps(payload)
    return f"{_b64(header_json.encode())}.{_b64(payload_json.encode())}.{_b64(secret.encode())}"


def decode(token, secret, algorithms=None, options=None):
    header_b64, payload_b64, sig = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    if sig != _b64(secret.encode()):
        raise _DummyException("bad signature")
    return payload

jwt_mod.encode = encode
# Do not override decode if another test has set it
if not hasattr(jwt_mod, "decode"):
    jwt_mod.decode = decode

from jwtek.core import ui

ui.info = lambda *a, **k: None
ui.success = lambda *a, **k: None
ui.warn = lambda *a, **k: None
ui.section = lambda *a, **k: None

from jwtek.core import forge, parser


def test_forge_hs256_decodable(capsys):
    payload = {"user": "alice"}
    forge.forge_jwt("HS256", json.dumps(payload), secret="secret")
    token = capsys.readouterr().out.splitlines()[-1]
    header, decoded, signature = parser.decode_jwt(token)
    assert header["alg"] == "HS256"
    assert decoded == payload
    assert signature == _b64(b"secret")


def test_forge_none_decodable(capsys):
    payload = {"foo": "bar"}
    forge.forge_jwt("none", json.dumps(payload))
    token = capsys.readouterr().out.splitlines()[-1]
    header, decoded, signature = parser.decode_jwt(token)
    assert header["alg"] == "none"
    assert decoded == payload
    assert signature == ""


def test_forge_hs256_missing_secret():
    with mock.patch("jwtek.core.ui.error") as err:
        forge.forge_jwt("HS256", "{}")
        err.assert_called()
