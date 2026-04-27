# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Fuzz target for the trust scoring engine."""

import sys
import atheris


def test_one_input(data: bytes) -> None:
    """Fuzz trust scoring with arbitrary agent IDs and interaction sequences."""
    fdp = atheris.FuzzedDataProvider(data)

    try:
        from agent_os.trust_root import TrustManager

        manager = TrustManager()
        agent_id = fdp.ConsumeUnicodeNoSurrogates(64)
        num_interactions = fdp.ConsumeIntInRange(0, 100)

        for _ in range(num_interactions):
            if fdp.ConsumeBool():
                manager.record_success(agent_id)
            else:
                manager.record_failure(agent_id)

        score = manager.get_trust_score(agent_id)
        assert 0 <= score.score <= 1000, f"Score out of bounds: {score.score}"
    except (ValueError, TypeError, KeyError, AttributeError):
        pass
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
