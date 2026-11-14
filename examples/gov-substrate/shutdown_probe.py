"""Exercise the actual callback against a real operator endpoint with a bad credential."""

import json
import sys
from pathlib import Path

from agentmesh.identity.agent_id import AgentIdentity
from bridge import TrustedBridge
from transport import UnixClient

configuration = json.loads(Path("/config/controller.json").read_text(encoding="utf-8"))
bridge = TrustedBridge(
    AgentIdentity.model_validate(configuration["identity"]),
    configuration["session_id"],
    UnixClient("/substrate/api.sock", configuration["agent_token"]),
    UnixClient("/operator/stop.sock", "invalid-control-credential"),
    "unused",
    configuration["actor"],
)
bridge.workers = json.loads(sys.argv[1])
print(json.dumps(bridge.shutdown()))
