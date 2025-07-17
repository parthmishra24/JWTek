import subprocess
from unittest import mock
from jwtek.__main__ import update_jwtek

def test_update_no_git(capsys):
    with mock.patch('subprocess.run', side_effect=FileNotFoundError()):
        update_jwtek()
    out = capsys.readouterr().out
    assert 'Cannot update. JWTEK was not installed via Git' in out

def test_update_local_changes(capsys):
    def fake_run(cmd, *a, **k):
        if cmd[:3] == ['git', 'rev-parse', '--is-inside-work-tree']:
            return subprocess.CompletedProcess(cmd, 0, stdout='true\n')
        if cmd[:3] == ['git', 'status', '--porcelain']:
            return subprocess.CompletedProcess(cmd, 0, stdout=' M file\n')
        raise AssertionError('unexpected command')
    with mock.patch('subprocess.run', side_effect=fake_run):
        update_jwtek()
    out = capsys.readouterr().out
    assert 'local changes' in out
