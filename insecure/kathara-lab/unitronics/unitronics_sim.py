#!/usr/bin/env python3
"""
Minimal stand-in for a Unitronics Vision-series PLC/HMI, modelling the
specific vulnerable behaviours described in CISA AA23-335A:

  - Listens on TCP 20256 by default (the real device's control port).
  - No password required to authenticate (T1078.001 - Default Accounts).
  - Ladder logic can be overwritten (T1565.001 - Stored Data Manipulation).
  - Device name can be changed, locking out the legitimate engineering
    workstation which needs it to reconnect (T1531 - Account Access Removal).
  - Upload/download functions can be disabled (T1499 - Endpoint DoS).
  - Listening port can be "changed" (T1499) - reflected in state; the
    session must reconnect to the new port to continue, same as the
    real device.
  - A splash/defacement message can be pushed (T1491.001 - Defacement).

No real ICS protocol is implemented - this is a plaintext line protocol
so it can be driven with `nc` for the exercise. Intentionally NOT hardened.
"""
import json
import os
import socket
import threading

STATE_FILE = "/state/unitronics_state.json"
DEFAULT_PORT = 20256

DEFAULT_STATE = {
    "device_name": "UNITRONICS-PLC-01",
    "port": DEFAULT_PORT,
    "software_version": "9.9.00",
    "ladder_logic": "MAIN_PROGRAM: (original control logic, not shown)",
    "upload_enabled": True,
    "download_enabled": True,
    "locked_password": None,   # set once actor "enables password protection"
    "splash_message": None,
}


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return dict(DEFAULT_STATE)


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


HELP = (
    "Commands: LOGIN <password|blank>, WHOAMI, GET_LOGIC, PUT_LOGIC <text>, "
    "RENAME <name>, SET_VERSION <ver>, SET_PORT <port>, "
    "DISABLE_UPLOAD, DISABLE_DOWNLOAD, LOCK_UPLOAD <password>, "
    "DEFACE <message>, QUIT"
)


def handle_client(conn, addr, lock):
    conn.sendall(b"UNITRONICS VISION SIM READY\r\n" + HELP.encode() + b"\r\n")
    authed = False
    with conn.makefile("rwb") as f:
        while True:
            line = f.readline()
            if not line:
                break
            cmd_line = line.decode(errors="ignore").strip()
            if not cmd_line:
                continue
            parts = cmd_line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            with lock:
                state = load_state()

                if cmd == "LOGIN":
                    # Vuln: default/blank password accepted unless the
                    # actor previously set one with LOCK_UPLOAD.
                    required = state.get("locked_password")
                    if not required or arg == required:
                        authed = True
                        f.write(b"OK LOGIN\r\n")
                    else:
                        f.write(b"ERR BAD_PASSWORD\r\n")

                elif not authed and cmd not in ("QUIT",):
                    f.write(b"ERR NOT_AUTHENTICATED (try LOGIN)\r\n")

                elif cmd == "WHOAMI":
                    f.write(json.dumps(state).encode() + b"\r\n")

                elif cmd == "GET_LOGIC":
                    f.write(state["ladder_logic"].encode() + b"\r\n")

                elif cmd == "PUT_LOGIC":
                    state["ladder_logic"] = arg
                    save_state(state)
                    f.write(b"OK LOGIC_REPLACED\r\n")

                elif cmd == "RENAME":
                    state["device_name"] = arg
                    save_state(state)
                    f.write(b"OK RENAMED\r\n")

                elif cmd == "SET_VERSION":
                    state["software_version"] = arg
                    save_state(state)
                    f.write(b"OK VERSION_SET\r\n")

                elif cmd == "SET_PORT":
                    state["port"] = int(arg)
                    save_state(state)
                    f.write(b"OK PORT_CHANGED (reconnect on new port)\r\n")

                elif cmd == "DISABLE_UPLOAD":
                    state["upload_enabled"] = False
                    save_state(state)
                    f.write(b"OK UPLOAD_DISABLED\r\n")

                elif cmd == "DISABLE_DOWNLOAD":
                    state["download_enabled"] = False
                    save_state(state)
                    f.write(b"OK DOWNLOAD_DISABLED\r\n")

                elif cmd == "LOCK_UPLOAD":
                    state["locked_password"] = arg
                    save_state(state)
                    f.write(b"OK UPLOAD_LOCKED\r\n")

                elif cmd == "DEFACE":
                    state["splash_message"] = arg
                    save_state(state)
                    f.write(b"OK SPLASH_SET\r\n")

                elif cmd == "QUIT":
                    f.write(b"BYE\r\n")
                    f.flush()
                    break

                else:
                    f.write(b"ERR UNKNOWN_COMMAND\r\n")
                f.flush()
    conn.close()


def main():
    state = load_state()
    save_state(state)
    port = state.get("port", DEFAULT_PORT)
    lock = threading.Lock()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    print(f"[plc-unitronics-sim] listening on :{port}, auth=NONE by default")

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr, lock), daemon=True).start()


if __name__ == "__main__":
    main()
