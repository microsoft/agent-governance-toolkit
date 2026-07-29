# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run the Healthcare MAF adapter example with native ACS."""

from pathlib import Path

from agt.policies.runtime import AgtRuntime
from agent_os.integrations.maf_adapter import MAFKernel


def main() -> None:
    root = Path(__file__).resolve().parent
    runtime = AgtRuntime.from_manifest(
        root / "policies" / "manifest.yaml"
    )
    try:
        kernel = MAFKernel(runtime=runtime)
        context = kernel.create_context("healthcare-example")
        for prompt in ("Review the current request", 'Patient MRN: 123456'):
            result = kernel.evaluate_input(context, prompt)
            print(prompt, result.verdict)
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
