#!/usr/bin/env python3
"""
lab/app.py — an intentionally-insecure demo web app for SAFE local testing.

Run it, point vulnscan at http://127.0.0.1:8000, and see the engine light up —
without touching any real system. Stdlib only (no Flask needed).

    python3 lab/app.py
    python3 vulnscan.py http://127.0.0.1:8000 --profile web --yes

DO NOT expose this to the internet. It is deliberately vulnerable.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = """<!DOCTYPE html><html><head><title>Vulnerable Lab</title></head><body>
<h1>Insecure Demo App</h1>
<form action="/login" method="post">
  <input name="username"><input type="password" name="password">
  <button>Login</button>
</form>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="document"><button>Upload</button>
</form>
<a href="/admin">admin</a>
<p>Search results for: __Q__</p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, extra=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # deliberately insecure: no CSP/HSTS/X-Frame-Options, weak cookie, version banner
        self.send_header("Set-Cookie", "session=deadbeef; Path=/")
        self.send_header("Server", "Apache/2.4.18 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.2.0")
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        q = ""
        if "?" in self.path and "q=" in self.path:
            q = self.path.split("q=", 1)[1].split("&", 1)[0]   # reflected, unescaped
        self._send(PAGE.replace("__Q__", q))

    def do_POST(self):
        self._send("<p>received</p>")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("Vulnerable lab on http://127.0.0.1:8000  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
