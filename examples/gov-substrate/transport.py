"""Local role-separated JSON transport for the integration example."""

# cspell:ignore PEERCRED

import json
import socket
import struct
import threading
from pathlib import Path

import httpx
import uvicorn


class UnixClient:
    def __init__(self, path, token=None, timeout=30):
        self.path, self.token, self.timeout = str(path), token, timeout

    def request(self, method, path, body=None, session=None):
        headers = {}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if session:
            headers["X-Session-Token"] = session
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=self.path),
            base_url="http://localhost",
            timeout=self.timeout,
            trust_env=False,
        ) as client:
            response = client.request(method, path, json=body, headers=headers)
            response.raise_for_status()
            return response.json()


class RoleSocket(socket.socket):
    def __init__(self, path, uid, mode):
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uid = uid
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.bind(path)
        Path(path).chmod(mode)
        self.listen(128)

    def accept(self):
        connection, address = super().accept()
        try:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12
            )
            allowed = struct.unpack("3i", credentials)[1] == self.uid
        except (OSError, struct.error):
            allowed = False
        if not allowed:
            connection.close()
            raise ConnectionAbortedError("unauthorized local peer")
        return connection, address


def serve_roles(roles):
    """Each socket has its own application and permitted Linux peer UID."""
    servers, threads = [], []
    for application, path, uid, mode in roles:
        listener = RoleSocket(path, uid, mode)
        server = uvicorn.Server(uvicorn.Config(application, log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]})
        thread.start()
        servers.append(server)
        threads.append(thread)
    try:
        for thread in threads:
            thread.join()
    finally:
        for server in servers:
            server.should_exit = True
        for thread in threads:
            thread.join(30)


if __name__ == "__main__":
    import sys

    body = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
    print(json.dumps(UnixClient(sys.argv[1]).request(sys.argv[2], sys.argv[3], body)))
