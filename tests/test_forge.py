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


def test_convert_rs256_to_none(tmp_path, capsys):
    payload = {"foo": "bar"}
    priv = tmp_path / "priv.pem"
    priv.write_text("privkey")
    forge.forge_jwt("RS256", json.dumps(payload), privkey_path=str(priv))
    rs_token = capsys.readouterr().out.splitlines()[-1]
    forge.forge_jwt("none", token=rs_token)
    new_token = capsys.readouterr().out.splitlines()[-1]
    header, decoded, signature = parser.decode_jwt(new_token)
    assert header["alg"] == "none"
    assert decoded == payload
    assert signature == ""


def test_convert_hs256_to_rs256(tmp_path, capsys):
    payload = {"user": "bob"}
    forge.forge_jwt("HS256", json.dumps(payload), secret="secret")
    hs_token = capsys.readouterr().out.splitlines()[-1]
    priv = tmp_path / "priv.pem"
    priv.write_text("privkey")
    forge.forge_jwt("RS256", token=hs_token, privkey_path=str(priv))
    new_token = capsys.readouterr().out.splitlines()[-1]
    header, decoded, signature = parser.decode_jwt(new_token)
    assert header["alg"] == "RS256"
    assert decoded == payload
    assert signature == _b64(b"privkey")


def test_convert_rs256_to_hs256(tmp_path, capsys):
    payload = {"user": "bob"}
    priv = tmp_path / "priv.pem"
    priv.write_text("privkey")
    forge.forge_jwt("RS256", json.dumps(payload), privkey_path=str(priv))
    rs_token = capsys.readouterr().out.splitlines()[-1]
    forge.forge_jwt("HS256", token=rs_token, secret="secret")
    new_token = capsys.readouterr().out.splitlines()[-1]
    header, decoded, signature = parser.decode_jwt(new_token)
    assert header["alg"] == "HS256"
    assert decoded == payload
    assert signature == _b64(b"secret")


def _set_inputs(monkeypatch, responses):
    iterator = iter(responses)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(iterator))


def test_interactive_edit_payload_multiple_fields(monkeypatch, capsys):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"email": "old@example.com", "userid": 1}
    _set_inputs(
        monkeypatch,
        [
            "payload",
            "email,userid",
            "new@example.com",
            "42",
            "n",
            "y",
            "secret",
        ],
    )

    forge.interactive_edit(header, payload, "sig")
    output_lines = [line for line in capsys.readouterr().out.strip().splitlines() if line]
    token = output_lines[-1]
    new_header, new_payload, signature = parser.decode_jwt(token)
    assert new_header["alg"] == "HS256"
    assert new_payload["email"] == "new@example.com"
    assert new_payload["userid"] == 42
    assert signature == _b64(b"secret")


def test_interactive_edit_change_alg_to_none(monkeypatch, capsys):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "alice"}
    _set_inputs(
        monkeypatch,
        [
            "header",
            "alg",
            "none",
            "n",
            "y",
        ],
    )

    forge.interactive_edit(header, payload, "sig")
    output_lines = [line for line in capsys.readouterr().out.strip().splitlines() if line]
    token = output_lines[-1]
    new_header, new_payload, signature = parser.decode_jwt(token)
    assert new_header["alg"] == "none"
    assert new_payload == payload
    assert signature == "sig"


def test_interactive_edit_signature_for_none(monkeypatch, capsys):
    header = {"alg": "none", "typ": "JWT"}
    payload = {"user": "alice"}
    _set_inputs(
        monkeypatch,
        [
            "signature",
            "tampered",
            "n",
            "y",
        ],
    )

    forge.interactive_edit(header, payload, "")
    output_lines = [line for line in capsys.readouterr().out.strip().splitlines() if line]
    token = output_lines[-1]
    new_header, new_payload, signature = parser.decode_jwt(token)
    assert new_header["alg"] == "none"
    assert new_payload == payload
    assert signature == "tampered"
