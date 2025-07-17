import sys
import types

# Provide dummy termcolor before importing ui
sys.modules.setdefault(
    "termcolor",
    type("Dummy", (), {"cprint": lambda *a, **k: None})(),
)

from jwtek.core import ui

# Stub ui functions to suppress output
ui.info = lambda *a, **k: None
ui.success = lambda *a, **k: None
ui.warn = lambda *a, **k: None
ui.error = lambda *a, **k: None
ui.section = lambda *a, **k: None

# Dummy jwt module (may already exist from other tests)
class _DummyException(Exception):
    pass

jwt_mod = sys.modules.setdefault("jwt", types.ModuleType("jwt"))
exc_mod = sys.modules.setdefault("jwt.exceptions", types.ModuleType("jwt.exceptions"))
exc_mod.InvalidSignatureError = _DummyException
exc_mod.DecodeError = _DummyException
jwt_mod.exceptions = exc_mod


def make_decode(correct_secret):
    def _decode(token, secret, algorithms=None, options=None):
        if secret == correct_secret:
            return {"msg": "ok"}
        raise _DummyException
    return _decode
jwt_mod.decode = make_decode("s3cr3t")

from jwtek.core import bruteforce


def test_bruteforce_success(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("foo\ns3cr3t\nbar\n")
    secret = bruteforce.bruteforce_hmac_secret("token", str(wordlist))
    assert secret == "s3cr3t"


def test_bruteforce_failure(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("foo\nbar\n")
    secret = bruteforce.bruteforce_hmac_secret("token", str(wordlist))
    assert secret is None

