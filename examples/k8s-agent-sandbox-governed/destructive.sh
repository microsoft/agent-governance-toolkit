# Fixture script: not a real destructive payload.
# Deliberately classified as "destructive" by run_agent.py's
# _DESTRUCTIVE_PATTERNS so the deny path in the Quick Start can be
# demonstrated safely, without ever running an actual disk-wipe command
# (which would also trip most repo/CI secret and payload scanners).
rm -rf /nonexistent-governance-test-path
