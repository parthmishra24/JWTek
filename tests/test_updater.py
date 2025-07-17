import jwtek.core.updater as updater


def _run_update(monkeypatch, version):
    calls = {}

    class FakeResult:
        returncode = 0
        stderr = ''

    def fake_run(cmd, capture_output=True, text=True):
        calls['cmd'] = cmd
        return FakeResult()

    monkeypatch.setattr(updater.subprocess, 'run', fake_run)
    monkeypatch.setattr(updater.ui, 'info', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'success', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'error', lambda *a, **k: None)
    monkeypatch.setattr(updater, 'pip_version', version)

    updater.update_tool(repo_url='https://github.com/example/repo.git', branch='dev')
    return calls['cmd']


def test_update_tool_includes_flag_for_new_pip(monkeypatch):
    cmd = _run_update(monkeypatch, '23.1')
    assert cmd == [
        'python3', '-m', 'pip', 'install', '--upgrade',
        '--break-system-packages',
        'git+https://github.com/example/repo.git@dev'
    ]
