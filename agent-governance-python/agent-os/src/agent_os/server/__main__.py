# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run Agent OS Governance API server."""

import argparse
import os

import uvicorn

from agent_os.server.app import GovServer


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent OS Governance API server")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "info"))
    args = parser.parse_args()

    server = GovServer()
    uvicorn.run(server.app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
