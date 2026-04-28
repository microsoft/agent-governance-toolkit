# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run AgentMesh Registry server."""

import argparse
import os

import uvicorn

from agentmesh.registry.app import RegistryServer


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentMesh Registry server")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8082")))
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "info"))
    args = parser.parse_args()

    server = RegistryServer()
    uvicorn.run(server.app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
