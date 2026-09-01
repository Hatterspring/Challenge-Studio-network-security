#!/usr/bin/env python3
"""
Deliberately vulnerable "perimeter appliance" admin panel.
Stand-in for an unpatched edge device (T1190 - Exploit Public-Facing Application).

Vulnerabilities baked in on purpose (documented for the defence writeup):
  1. Auth bypass: any request to /admin with ?debug=1 skips the login check.
  2. A world-readable backup config leaks a domain admin credential
     (T1552 - Unsecured Credentials) at /backup/config.bak.
  3. Login form itself accepts a weak default admin/admin123.

This is intentionally a toy HTTP server (stdlib only, no deps) so it runs
on a bare kathara/base image.
"""
import http.server
import socketserver
import urllib.parse

PORT = 8080
VALID_USER = "admin"
VALID_PASS = "admin123"

BACKUP_CONFIG = b"""# appliance backup config - auto-generated, do not distribute
vpn.local_admin=admin
vpn.local_pass=admin123
ad.domain=CORP.LOCAL
ad.svc_account=CORP\\\\svc_backup
ad.svc_password=Summer2026!
# ^ service account holds Domain Admin - reused across appliance + AD
"""

LOGIN_PAGE = """<html><body>
<h2>Perimeter Appliance - Admin Login</h2>
<form method="POST" action="/admin">
  <input name="user" placeholder="username"><br>
  <input name="pass" type="password" placeholder="password"><br>
  <button type="submit">Login</button>
</form>
</body></html>"""

DASHBOARD_PAGE = """<html><body>
<h2>Perimeter Appliance - Dashboard</h2>
<p>Status: OK</p>
<p><a href="/backup/config.bak">Download last config backup</a></p>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/backup/config.bak":
            # Vuln: no auth required, no path restriction.
            self._send(200, BACKUP_CONFIG, "text/plain")
            return

        if parsed.path == "/admin":
            if qs.get("debug", ["0"])[0] == "1":
                # Vuln: auth bypass
                self._send(200, DASHBOARD_PAGE)
                return
            self._send(200, LOGIN_PAGE)
            return

        self._send(200, "<html><body><h1>Appliance OK</h1></body></html>")

    def do_POST(self):
        if self.path == "/admin":
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode())
            user = data.get("user", [""])[0]
            pwd = data.get("pass", [""])[0]
            if user == VALID_USER and pwd == VALID_PASS:
                self._send(200, DASHBOARD_PAGE)
            else:
                self._send(401, "<html><body>Login failed</body></html>")
            return
        self._send(404, "Not found")

    def log_message(self, fmt, *args):
        print("[edge-fw]", fmt % args)


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"[edge-fw] listening on :{PORT}")
        httpd.serve_forever()
