from pathlib import Path

import sys

from jwtek.__main__ import main
from jwtek.core import scraper, extractor, parser, static_analysis, ui


def test_save_path_option(monkeypatch, tmp_path):
    save_file = tmp_path / "custom.txt"
    called = {}

    def fake_login_and_scrape(login, dashboard, out_path):
        called["out_path"] = out_path
        Path(out_path).write_text("a.b.c")

    def fake_extract_from_file(path):
        called["extract_path"] = path
        return "a.b.c"

    monkeypatch.setattr(scraper, "login_and_scrape", fake_login_and_scrape)
    monkeypatch.setattr(extractor, "extract_from_file", fake_extract_from_file)
    monkeypatch.setattr(parser, "decode_jwt", lambda token: ({}, {}, ""))
    monkeypatch.setattr(parser, "pretty_print_jwt", lambda h, p, s: None)
    monkeypatch.setattr(static_analysis, "run_all_checks", lambda h, p: None)
    monkeypatch.setattr(ui, "section", lambda x: None)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "jwtek",
            "analyze",
            "-l",
            "http://login",
            "-d",
            "http://dashboard",
            "-S",
            str(save_file),
        ],
    )

    main()

    assert called["out_path"] == str(save_file)
    assert called["extract_path"] == str(save_file)
