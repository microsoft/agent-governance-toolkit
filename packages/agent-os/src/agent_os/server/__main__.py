# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run Agent OS Governance API server."""

import uvicorn

from agent_os.server.app import GovServer


def main() -> None:
    server = GovServer()
    uvicorn.run(server.app, host="127.0.0.1", port=8080, log_level="info")


if __name__ == "__main__":
    main()
