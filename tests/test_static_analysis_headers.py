import jwtek.core.static_analysis as sa
from unittest import mock

def test_check_jku_warns():
    header = {'jku': 'http://evil.com/jwks.json'}
    with mock.patch('jwtek.core.ui.warn') as warn:
        sa.check_jku_x5u(header)
        warn.assert_called()
        assert 'jku' in warn.call_args[0][0]

def test_check_x5u_warns():
    header = {'x5u': 'http://evil.com/cert.pem'}
    with mock.patch('jwtek.core.ui.warn') as warn:
        sa.check_jku_x5u(header)
        warn.assert_called()
        assert 'x5u' in warn.call_args[0][0]

def test_suspicious_kid_url():
    header = {'kid': 'http://attacker/key'}
    with mock.patch('jwtek.core.ui.warn') as warn:
        sa.check_suspicious_kid(header)
        warn.assert_called()
        assert 'kid' in warn.call_args[0][0]
