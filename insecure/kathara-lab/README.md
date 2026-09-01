# Vulnerable IT/OT Kathara Lab

Supports three attack chains against one topology:
- **AA24-038A** (Volt Typhoon) - IT-to-OT identity pivot
- **AA23-335A** (CyberAv3ngers / Unitronics, 2023) - direct-to-OT, default creds
- **AA26-097A** (Iranian PLC campaign, 2026) - direct-to-OT, legit-protocol abuse + persistence

## Run it

```
kathara lstart
```

All services are plaintext line-protocols or plain HTTP by design - use `nc`,
`curl`, or a browser to interact, so you can focus on the attack logic rather
than protocol tooling.

## IP plan

| Network | CIDR |
|---|---|
| internet | 10.0.0.0/24 |
| dmz | 172.16.0.0/24 |
| it_lan | 10.10.10.0/24 |
| ot_dmz | 10.20.20.0/24 |
| ot_lan | 10.30.30.0/24 |

| Host | Address(es) | Key ports |
|---|---|---|
| attacker | 10.0.0.10 | - |
| edge-fw | 10.0.0.1 / 172.16.0.1 | 8080 (HTTP admin) |
| rtr-dmz-it | 172.16.0.254 / 10.10.10.254 | - |
| dc01 | 10.10.10.10 | 88, 389, 445 (Samba AD) |
| fileserver | 10.10.10.20 | 445 (SMB) |
| admin-ws | 10.10.10.30 | 3389 (RDP) |
| rtr-it-ot | 10.10.10.253 / 10.20.20.254 | - |
| jumpbox | 10.20.20.5 / 10.30.30.5 | 22 (SSH), 8888 (relay) |
| plc-unitronics-sim | 10.30.30.11 / 172.16.0.11 | 20256 |
| plc-rockwell-sim | 10.30.30.12 / 172.16.0.12 | 44818, 22 (dropbear) |
| hmi-scada | 10.30.30.20 | 80 |

## Deliberate vulnerabilities (for your defence writeup)

| # | Location | Weakness | Maps to |
|---|---|---|---|
| 1 | edge-fw | Auth bypass via `?debug=1`; weak default creds `admin/admin123` | AA24-038A, T1190 |
| 2 | edge-fw | Backup config leaks AD service-account credential | AA24-038A, T1552 |
| 3 | dc01 | `svc_backup` account is Domain Admin, reuses the leaked password | AA24-038A, T1078 |
| 4 | fileserver | Guest-writable share exposes an OT network/credential reference doc | AA24-038A, T1048 |
| 5 | admin-ws | Plaintext "saved session" file with OT jumpbox credential | AA24-038A, T1552/T1012 |
| 6 | jumpbox | Reachable with weak reused OT credential; pre-built relay shows pivot technique | AA24-038A, T1090.001 |
| 7 | plc-unitronics-sim | No password required by default; full remote logic/name/port control | AA23-335A, T1078.001/T1565.001/T1531/T1499/T1491.001 |
| 8 | plc-rockwell-sim | Zero authentication on the control protocol at all | AA26-097A, T0883 |
| 9 | plc-rockwell-sim | Project file downloadable by anyone who connects | AA26-097A, project-file exfil |
| 10 | plc-rockwell-sim | Dropbear SSH with weak root password, running by default | AA26-097A, persistence |
| 11 | hmi-scada | Renders PLC-reported values with zero independent validation | AA26-097A, falsified display impact |
| 12 | Topology | plc-*-sim nodes are dual-homed onto `dmz` directly, bypassing all segmentation | AA23-335A / AA26-097A root cause |

## Suggested "hardened" follow-up lab

Once you've run all three chains, fork this lab.conf and:
- Drop the `dmz` interface from both plc-*-sim nodes (kills direct exposure).
- Require `LOGIN <password>` on plc-unitronics-sim by pre-seeding `locked_password` in its state file.
- Add a shared-secret handshake requirement to rockwell_sim.py before `SET_TAG`/`GET_PROJECT` are accepted.
- Replace edge-fw's debug bypass and default creds with real auth.
- Rotate `svc_backup`'s password off the value leaked in edge-fw's backup file.
- Add a sanity-check in hmi_app.py (e.g. rate-of-change limits) that flags implausible tag jumps.

Re-running your attack chains against the hardened version - and documenting
what broke and why - is the comparison your studio report will want.
