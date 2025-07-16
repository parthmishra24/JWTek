import jwtek.core.updater as updater


def test_update_tool_runs_pip(monkeypatch):
    calls = {}

    def fake_check_call(cmd):
        calls['cmd'] = cmd

    monkeypatch.setattr(updater.subprocess, 'check_call', fake_check_call)
    monkeypatch.setattr(updater.ui, 'info', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'success', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'error', lambda *a, **k: None)

    updater.update_tool()

    assert calls['cmd'] == [
        'pip',
        'install',
        '--upgrade',
        'git+https://github.com/parthmishra24/JWTek.git@main',
    ]

