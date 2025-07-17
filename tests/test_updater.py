import jwtek.core.updater as updater


def test_update_tool_runs_pip(monkeypatch):
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

    updater.update_tool(repo_url='https://github.com/example/repo.git', branch='dev')
    assert calls['cmd'] == [
        'python3', '-m', 'pip', 'install', '--upgrade',
        '--break-system-packages',
        'git+https://github.com/example/repo.git@dev'
    ]


def test_update_tool_prints_stderr(monkeypatch):
    messages = {}

    class FakeResult:
        returncode = 1
        stderr = 'boom'

    def fake_run(cmd, capture_output=True, text=True):
        return FakeResult()

    def fake_error(msg):
        messages['msg'] = msg

    monkeypatch.setattr(updater.subprocess, 'run', fake_run)
    monkeypatch.setattr(updater.ui, 'info', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'success', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'error', fake_error)

    updater.update_tool(repo_url='https://github.com/example/repo.git', branch='dev')

    assert 'boom' in messages.get('msg', '')

