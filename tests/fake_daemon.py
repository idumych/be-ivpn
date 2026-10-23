#!/usr/bin/env python3
"""Minimal stand-in for ivpn-service, mirroring its wire protocol:
newline-delimited JSON over 127.0.0.1, first message must be Hello with the
secret from port.txt; wrong secret -> ErrorResp + hang up.

Usage: fake_daemon.py <port-file-path>
Writes "<port>:<hex secret>" to the given path and serves until killed.
"""
import json
import os
import secrets
import socket
import sys
import threading


def send(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def big_server_list():
    servers = []
    for i in range(400):
        servers.append({
            "gateway": f"x{i}.wg.ivpn.net", "country_code": "NL",
            "country": "Netherlands", "city": f"City {i}",
            "hosts": [{"hostname": f"x{i}a.wg.ivpn.net", "host": f"10.0.{i // 250}.{i % 250}",
                       "public_key": "k" * 44, "local_ip": "172.16.0.1/12"}],
        })
    return {"wireguard": servers, "openvpn": [], "config": {"ports": {}}}


def handle(conn, secret):
    buf = b""
    verified = False
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                req = json.loads(line)
                cmd = req.get("Command")
                idx = req.get("Idx")
                if not verified:
                    if cmd != "Hello":
                        return
                    if req.get("Secret") != secret or not isinstance(req.get("Secret"), int):
                        send(conn, {"Command": "ErrorResp", "Idx": idx,
                                    "ErrorMessage": "secret verification error"})
                        return
                    assert req.get("ClientType") == 0
                    assert req.get("GetServersList") is True
                    verified = True
                    if os.environ.get("HELLO_DUMP"):
                        with open(os.environ["HELLO_DUMP"], "wb") as f:
                            f.write(line)
                    send(conn, {"Command": "HelloResp", "Idx": idx, "Version": "3.14.0",
                                "Session": {"AccountID": "i-TEST-TEST-TEST"},
                                "ParanoidMode": {"IsEnabled": False}})
                    send(conn, {"Command": "ServerListResp", "Idx": 0,
                                "VpnServers": big_server_list()})
                elif cmd == "KillSwitchGetStatus":
                    assert "ProtocolSecret" in req
                    send(conn, {"Command": "KillSwitchStatusResp", "Idx": idx,
                                "IsEnabled": False, "IsPersistent": False})
                elif cmd == "TestCloseConnection":
                    conn.shutdown(socket.SHUT_RDWR)
                    return
                else:
                    send(conn, {"Command": "EmptyResp", "Idx": idx})


def main():
    port_file = sys.argv[1]
    secret = secrets.randbits(64) | (1 << 63)  # exercise full uint64 range
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    tmp = port_file + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{port}:{secret:x}")
    os.rename(tmp, port_file)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, secret), daemon=True).start()


if __name__ == "__main__":
    main()
