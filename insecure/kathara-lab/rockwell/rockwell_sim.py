#!/usr/bin/env python3
"""
Minimal stand-in for a Rockwell CompactLogix/Micro850-style controller,
modelling the behaviours described in CISA AA26-097A:

  - Listens on TCP 44818 (the real EtherNet/IP port) with NO authentication
    at all - the advisory's point is that actors used the *legitimate*
    engineering protocol, not an exploit (architectural exposure, not a bug).
  - Exposes a "project file" (.ACD stand-in) containing ladder logic /
    config, downloadable by anyone who connects (project-file exfiltration).
  - Exposes readable/writable "tags" (registers) that a HMI polls to show
    live values - writing a tag while leaving the HMI's cached/alarm view
    unaffected is how the advisory's "falsified HMI/SCADA display" impact
    is modelled here (see hmi-scada, which deliberately does NOT flag
    mismatches - that's the vulnerability, not a bug in this sim).

Plaintext line protocol again, driven with `nc` for teaching purposes.
"""
import json
import os
import socket
import threading

PORT = 44818
STATE_FILE = "/state/rockwell_state.json"
PROJECT_FILE = "/state/project.ACD.txt"

DEFAULT_TAGS = {
    "TANK_LEVEL": 62.0,
    "PUMP_STATUS": "RUNNING",
    "ALARM_HIGH_LEVEL": False,
    "CHLORINE_DOSING_RATE": 3.2,
}

HELP = (
    "Commands: SESSION_REGISTER, GET_PROJECT, LIST_TAGS, "
    "GET_TAG <name>, SET_TAG <name> <value>, QUIT"
)


def load_tags():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return dict(DEFAULT_TAGS)


def save_tags(tags):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(tags, f, indent=2)


def handle_client(conn, lock):
    conn.sendall(b"ROCKWELL COMPACTLOGIX SIM (EtherNet/IP) - NO AUTH\r\n" + HELP.encode() + b"\r\n")
    with conn.makefile("rwb") as f:
        while True:
            line = f.readline()
            if not line:
                break
            cmd_line = line.decode(errors="ignore").strip()
            if not cmd_line:
                continue
            parts = cmd_line.split(" ", 2)
            cmd = parts[0].upper()

            with lock:
                if cmd == "SESSION_REGISTER":
                    f.write(b"OK SESSION 0xDEADBEEF\r\n")

                elif cmd == "GET_PROJECT":
                    with open(PROJECT_FILE, "rb") as pf:
                        data = pf.read()
                    f.write(f"OK {len(data)} bytes follow\r\n".encode())
                    f.write(data + b"\r\n")

                elif cmd == "LIST_TAGS":
                    tags = load_tags()
                    f.write(json.dumps(tags).encode() + b"\r\n")

                elif cmd == "GET_TAG":
                    tags = load_tags()
                    name = parts[1] if len(parts) > 1 else ""
                    f.write(str(tags.get(name, "ERR NO_SUCH_TAG")).encode() + b"\r\n")

                elif cmd == "SET_TAG":
                    tags = load_tags()
                    if len(parts) >= 3:
                        name, value = parts[1], parts[2]
                        # naive type coercion
                        if value.lower() in ("true", "false"):
                            value = value.lower() == "true"
                        else:
                            try:
                                value = float(value)
                            except ValueError:
                                pass
                        tags[name] = value
                        save_tags(tags)
                        f.write(b"OK TAG_SET\r\n")
                    else:
                        f.write(b"ERR USAGE: SET_TAG <name> <value>\r\n")

                elif cmd == "QUIT":
                    f.write(b"BYE\r\n")
                    f.flush()
                    break

                else:
                    f.write(b"ERR UNKNOWN_COMMAND\r\n")
                f.flush()
    conn.close()


def main():
    if not os.path.exists(STATE_FILE):
        save_tags(DEFAULT_TAGS)

    lock = threading.Lock()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(5)
    print(f"[plc-rockwell-sim] listening on :{PORT}, auth=NONE (legit-protocol abuse)")

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_client, args=(conn, lock), daemon=True).start()


if __name__ == "__main__":
    main()
