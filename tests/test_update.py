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


def test_update_up_to_date(capsys):
    calls = {'head': 0}

    def fake_run(cmd, *a, **k):
        if cmd[:3] == ['git', 'rev-parse', '--is-inside-work-tree']:
            return subprocess.CompletedProcess(cmd, 0, stdout='true\n')
        if cmd[:3] == ['git', 'status', '--porcelain']:
            return subprocess.CompletedProcess(cmd, 0, stdout='')
        if cmd[:3] == ['git', 'rev-parse', 'HEAD']:
            calls['head'] += 1
            return subprocess.CompletedProcess(cmd, 0, stdout='abc\n')
        if cmd[:4] == ['git', 'pull', 'origin', 'main']:
            return subprocess.CompletedProcess(cmd, 0, stdout='Already up to date.\n')
        raise AssertionError(f'unexpected command {cmd}')

    with mock.patch('subprocess.run', side_effect=fake_run):
        update_jwtek()

    out = capsys.readouterr().out
    assert 'already up to date' in out.lower()


def test_update_shows_commits(capsys):
    state = {'head': 0}

    def fake_run(cmd, *a, **k):
        if cmd[:3] == ['git', 'rev-parse', '--is-inside-work-tree']:
            return subprocess.CompletedProcess(cmd, 0, stdout='true\n')
        if cmd[:3] == ['git', 'status', '--porcelain']:
            return subprocess.CompletedProcess(cmd, 0, stdout='')
        if cmd[:3] == ['git', 'rev-parse', 'HEAD']:
            state['head'] += 1
            return subprocess.CompletedProcess(cmd, 0, stdout=('abc\n' if state['head'] == 1 else 'def\n'))
        if cmd[:4] == ['git', 'pull', 'origin', 'main']:
            return subprocess.CompletedProcess(cmd, 0, stdout='Updating\n')
        if cmd[0:2] == ['git', 'log']:
            assert cmd[2] == '--pretty=format:%s'
            assert cmd[3] == 'abc..def'
            return subprocess.CompletedProcess(cmd, 0, stdout='Fix bug\nAdd feature\n')
        raise AssertionError(f'unexpected command {cmd}')

    with mock.patch('subprocess.run', side_effect=fake_run):
        update_jwtek()

    out = capsys.readouterr().out
    assert 'JWTEK has been updated' in out
    assert '- Fix bug' in out
    assert '- Add feature' in out
