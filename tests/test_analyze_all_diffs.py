import base64
import json
import sys
import types

# Dummy modules for optional dependencies
class _DummyException(Exception):
    pass

dummy_jwt = types.ModuleType("jwt")
dummy_exceptions = types.ModuleType("jwt.exceptions")
dummy_exceptions.InvalidSignatureError = _DummyException
dummy_exceptions.DecodeError = _DummyException
dummy_jwt.exceptions = dummy_exceptions

sys.modules.setdefault("jwt", dummy_jwt)
sys.modules.setdefault("jwt.exceptions", dummy_exceptions)
sys.modules.setdefault("requests", type("Dummy", (), {})())
sys.modules.setdefault("termcolor", type("Dummy", (), {"cprint": lambda *a, **k: None})())

# Stub UI helpers to avoid colour output during tests
import jwtek.core.ui as ui
ui.info = lambda *a, **k: None
ui.success = lambda *a, **k: None
ui.warn = lambda *a, **k: None
ui.error = lambda *a, **k: None
ui.section = lambda *a, **k: None

from jwtek.__main__ import analyze_all_from_file


def forge_token(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    s = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
    return f"{h}.{p}.{s}"


def test_analyze_all_prints_diffs(tmp_path, capsys):
    token1 = forge_token({"id": 1})
    token2 = forge_token({"id": 2})
    path = tmp_path / "t.txt"
    path.write_text(f"{token1}\n{token2}\n")

    analyze_all_from_file(str(path))

    out = capsys.readouterr().out
    assert "Diff: token #1 vs token #2" in out
    assert "id: '1' -> '2'" in out
