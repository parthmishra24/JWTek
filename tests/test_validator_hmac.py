import sys
import types
from unittest import mock

# Provide dummy termcolor before importing ui
sys.modules.setdefault("termcolor", type("Dummy", (), {"cprint": lambda *a, **k: None})())

from jwtek.core import ui

# Silence ui output in tests
ui.info = lambda *a, **k: None
ui.success = lambda *a, **k: None
ui.warn = lambda *a, **k: None
ui.error = lambda *a, **k: None
ui.section = lambda *a, **k: None

# Dummy jwt module for validator
class _DummyException(Exception):
    pass

jwt_mod = sys.modules.setdefault("jwt", types.ModuleType("jwt"))
exc_mod = sys.modules.setdefault("jwt.exceptions", types.ModuleType("jwt.exceptions"))
exc_mod.InvalidSignatureError = _DummyException
jwt_exp = type("_Exp", (Exception,), {})
exc_mod.ExpiredSignatureError = jwt_exp
jwt_mod.InvalidSignatureError = _DummyException
jwt_mod.ExpiredSignatureError = jwt_exp
jwt_mod.exceptions = exc_mod


def make_decode(correct):
    def _decode(token, key, algorithms=None, options=None):
        if key == correct:
            return {"ok": True}
        raise _DummyException
    return _decode

from jwtek.core import validator


def test_verify_signature_hmac_success():
    jwt_mod.decode = make_decode("secret")
    with mock.patch("jwtek.core.ui.success") as success:
        validator.verify_signature_hmac("token", "secret")
        success.assert_called()


def test_verify_signature_hmac_failure():
    jwt_mod.decode = make_decode("secret")
    with mock.patch("jwtek.core.ui.error") as err:
        validator.verify_signature_hmac("token", "wrong")
        err.assert_called()
