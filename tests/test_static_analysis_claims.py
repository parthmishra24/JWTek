import jwtek.core.static_analysis as sa
from unittest import mock
from datetime import datetime


def test_check_expired_includes_timestamp():
    payload = {'exp': 50}
    with mock.patch('jwtek.core.ui.warn') as warn, mock.patch('time.time', return_value=100):
        sa.check_expired(payload)
        warn.assert_called()
        assert datetime.fromtimestamp(50).strftime("%Y-%m-%d %H:%M:%S") in warn.call_args[0][0]


def test_check_long_lifetime_includes_timestamps():
    iat = 1
    exp = 3600 * 24 * 8
    payload = {'iat': iat, 'exp': exp}
    with mock.patch('jwtek.core.ui.warn') as warn:
        sa.check_long_lifetime(payload)
        warn.assert_called()
        msg = warn.call_args[0][0]
        assert datetime.fromtimestamp(iat).strftime("%Y-%m-%d %H:%M:%S") in msg
        assert datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S") in msg


def test_check_suspicious_iat_includes_timestamp():
    iat = 1000000000
    payload = {'iat': iat}
    with mock.patch('jwtek.core.ui.warn') as warn, mock.patch('time.time', return_value=0):
        sa.check_suspicious_iat(payload)
        warn.assert_called()
        assert datetime.fromtimestamp(iat).strftime("%Y-%m-%d %H:%M:%S") in warn.call_args[0][0]
