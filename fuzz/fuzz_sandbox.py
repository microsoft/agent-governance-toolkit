# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Fuzz target for the sandbox AST validator."""

import sys
import atheris


def test_one_input(data: bytes) -> None:
    """Fuzz the sandbox code validator with arbitrary Python code."""
    try:
        code = data.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        from agent_os.sandbox import SandboxValidator

        validator = SandboxValidator()
        validator.validate_code(code)
    except (SyntaxError, ValueError, TypeError, AttributeError):
        pass
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
