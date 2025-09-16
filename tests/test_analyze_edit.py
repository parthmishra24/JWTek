import sys

from jwtek.__main__ import main
from jwtek.core import parser, static_analysis, ui, forge


def test_analyze_edit_invokes_interactive(monkeypatch):
    token = "a.b.c"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"email": "old@example.com"}
    signature = "sig"
    called = {}

    monkeypatch.setattr(parser, "decode_jwt", lambda t: (header, payload, signature))
    monkeypatch.setattr(parser, "pretty_print_jwt", lambda h, p, s: None)
    monkeypatch.setattr(static_analysis, "run_all_checks", lambda h, p: None)
    monkeypatch.setattr(ui, "section", lambda *a, **k: None)

    def fake_interactive_edit(h, p, s):
        called["data"] = (h, p, s)

    monkeypatch.setattr(forge, "interactive_edit", fake_interactive_edit)

    monkeypatch.setattr(sys, "argv", ["jwtek", "analyze", "-t", token, "-e"])

    main()

    assert called["data"][0] == header
    assert called["data"][1] == payload
    assert called["data"][2] == signature
