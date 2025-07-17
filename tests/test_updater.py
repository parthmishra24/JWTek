import jwtek.core.updater as updater


def test_update_tool_runs_pip(monkeypatch):
    calls = {}

    def fake_check_call(cmd):
        calls['cmd'] = cmd

    monkeypatch.setattr(updater.subprocess, 'check_call', fake_check_call)
    monkeypatch.setattr(updater.ui, 'info', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'success', lambda *a, **k: None)
    monkeypatch.setattr(updater.ui, 'error', lambda *a, **k: None)

    updater.update_tool(repo_url='https://github.com/example/repo.git', branch='dev')
    assert calls['cmd'] == [
        'python3', '-m', 'pip', 'install', '--upgrade',
        '--break-system-packages',
        'git+https://github.com/example/repo.git@dev'
    ]


def test_update_cli_forwards_args(monkeypatch):
    import jwtek.__main__ as cli

    called = {}

    def fake_update_tool(repo_url, branch):
        called['repo'] = repo_url
        called['branch'] = branch

    monkeypatch.setattr(cli.updater, 'update_tool', fake_update_tool)

    import sys
    monkeypatch.setattr(sys, 'argv', [
        'jwtek', 'update', '--repo', 'https://github.com/example/repo.git', '--branch', 'dev'
    ])

    cli.main()

    assert called == {
        'repo': 'https://github.com/example/repo.git',
        'branch': 'dev',
    }

