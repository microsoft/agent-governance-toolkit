"""Untrusted worker. Only its AGT tool socket is available."""

import hashlib
import http.client
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path


class LocalHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def request(body, path="/tools", socket_path="/bridge/tools.sock"):
    connection = LocalHTTP(socket_path, timeout=40)
    try:
        connection.request(
            "POST", path, json.dumps(body), {"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        return {"status": response.status, "body": json.loads(response.read())}
    finally:
        connection.close()


def bypasses():
    results = {}
    for target in (
        "/substrate/api.sock",
        "/operator/stop.sock",
        "/admin/controller.sock",
        "/var/run/docker.sock",
        "/config/controller.json",
        "/config/substrate.json",
        "/workspace",
        "/proof",
    ):
        results[target] = not os.path.exists(target)
    try:
        socket.create_connection(("198.51.100.1", 80), timeout=1).close()
        results["direct_network"] = False
    except OSError:
        results["direct_network"] = True
    try:
        Path("/etc/forbidden-write").write_text("bypass", encoding="utf-8")
        results["direct_write"] = False
    except OSError:
        results["direct_write"] = True
    results["operator_credentials_absent"] = not any(
        word in name.upper()
        for name in os.environ
        if name != "GPG_KEY"
        for word in ("TOKEN", "SECRET", "KEY", "PASSWORD")
    )
    return results


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "request":
        print(json.dumps(request(json.loads(sys.argv[2]))))
    elif len(sys.argv) > 1 and sys.argv[1] == "bypass":
        print(json.dumps(bypasses()))
    else:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        sealed = sys.stdin.buffer.read()
        Path("/tmp/ready").write_text(
            hashlib.sha256(sealed).hexdigest(), encoding="utf-8"
        )
        while True:
            time.sleep(1)
