#!/usr/bin/env python3
"""
Deliberately naive HMI/SCADA operator display.

Vulnerability modelled: it renders exactly whatever the PLC sims report,
with no independent validation, no discrepancy detection, and no operator
alerting if a value looks physically implausible. This is what lets the
AA26-097A-style "falsified display" impact work - the actor changes a tag
on plc-rockwell-sim and the operator screen calmly shows the fake value.
It also renders the Unitronics splash-defacement message verbatim if one
has been set, for the AA23-335A chain.
"""
import http.server
import json
import socket
import socketserver

HTTP_PORT = 80
UNITRONICS_HOST = ("10.30.30.11", 20256)
ROCKWELL_HOST = ("10.30.30.12", 44818)


def query_unitronics():
    try:
        with socket.create_connection(UNITRONICS_HOST, timeout=2) as s:
            f = s.makefile("rwb")
            f.readline()  # banner
            f.readline()  # help
            f.write(b"LOGIN\r\n")
            f.flush()
            f.readline()
            f.write(b"WHOAMI\r\n")
            f.flush()
            resp = f.readline().decode(errors="ignore").strip()
            return json.loads(resp)
    except Exception as e:
        return {"error": str(e)}


def query_rockwell_tags():
    try:
        with socket.create_connection(ROCKWELL_HOST, timeout=2) as s:
            f = s.makefile("rwb")
            f.readline()  # banner
            f.readline()  # help
            f.write(b"LIST_TAGS\r\n")
            f.flush()
            resp = f.readline().decode(errors="ignore").strip()
            return json.loads(resp)
    except Exception as e:
        return {"error": str(e)}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = query_unitronics()
        tags = query_rockwell_tags()

        splash_html = ""
        if isinstance(u, dict) and u.get("splash_message"):
            splash_html = f"<div style='background:red;color:white;padding:20px;font-size:24px'>{u['splash_message']}</div>"

        rows = ""
        if isinstance(tags, dict) and "error" not in tags:
            for k, v in tags.items():
                rows += f"<tr><td>{k}</td><td>{v}</td></tr>"
        else:
            rows = f"<tr><td colspan=2>PLC unreachable: {tags}</td></tr>"

        body = f"""<html><body>
        <h2>Plant SCADA Overview</h2>
        {splash_html}
        <h3>Live Tags (as reported by controller - no independent validation)</h3>
        <table border=1>{rows}</table>
        <p><i>Refresh to poll again.</i></p>
        </body></html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        print("[hmi-scada]", fmt % args)


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", HTTP_PORT), Handler) as httpd:
        print(f"[hmi-scada] listening on :{HTTP_PORT}")
        httpd.serve_forever()
