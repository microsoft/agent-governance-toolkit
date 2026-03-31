# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Fuzz target for the prompt injection detector."""

import sys
import atheris


def test_one_input(data: bytes) -> None:
    """Fuzz the prompt injection detector with arbitrary input."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        from agent_os.prompt_injection import PromptInjectionDetector

        detector = PromptInjectionDetector()
        detector.scan(text)
    except (ValueError, TypeError, KeyError, AttributeError):
        pass
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
