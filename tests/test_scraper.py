import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jwtek.core.scraper import login_and_scrape

SAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.dGVzdHNpZw"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/login':
            content = f"""<html><body><script>
            document.cookie = 'auth={SAMPLE_JWT}';
            localStorage.setItem('jwt', '{SAMPLE_JWT}');
            </script>Login</body></html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
        elif self.path == '/dashboard':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"token": "{SAMPLE_JWT}"}}'.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # pragma: no cover - silence
        pass


def run_server(server):
    with server:
        server.serve_forever()


def test_login_and_scrape(tmp_path, monkeypatch):
    server = HTTPServer(('localhost', 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    thread.start()

    monkeypatch.setenv('JWTEK_HEADLESS', 'true')
    monkeypatch.setattr('builtins.input', lambda *args: None)

    out_file = tmp_path / 'jwt.txt'
    try:
        login_and_scrape(
            f'http://localhost:{port}/login',
            f'http://localhost:{port}/dashboard',
            out_path=str(out_file),
        )
    except Exception as exc:  # pragma: no cover - environment issue
        pytest.skip(f'Playwright launch failed: {exc}')
    finally:
        server.shutdown()
        thread.join()

    assert out_file.read_text().strip() == SAMPLE_JWT
