"""Real end-to-end ACS demo.

A real Azure AI Content Safety annotator gates a REAL Azure OpenAI chat
completion through the ACS runtime. The user prompt is screened at the
`input` intervention point and the model's reply is screened at `output`;
between them the guarded execute() makes a live Azure OpenAI call.

Reads credentials from ~/rb/AgentControlSpecification/.env (Azure OpenAI +
Azure Content Safety). No secrets are printed.
"""

import asyncio
import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Mapping

from openai import AsyncAzureOpenAI

from agent_control_specification import AgentControl, AgentControlBlocked

MANIFEST = Path(__file__).resolve().parent / "manifest_real.yaml"
ENV = Path.home() / "rb" / "AgentControlSpecification" / ".env"


def load_env() -> None:
    for raw in ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _text_of(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("text", value))
    return "" if value is None else str(value)


class AzureContentSafetyAnnotator:
    """Host annotator that calls the real Azure AI Content Safety API."""

    def __init__(self) -> None:
        self._url = os.environ["AZURE_CONTENT_SAFETY_ENDPOINT"]
        self._key = os.environ["AZURE_CONTENT_SAFETY_KEY"]

    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input) -> Mapping[str, Any]:
        if annotator_name != "aacs":
            return {}
        text = _text_of(preliminary_policy_input["policy_target"]["value"])
        if not text.strip():
            return {"scores": {}}
        body = json.dumps({
            "text": text[:10000],
            "categories": ["Hate", "SelfHarm", "Sexual", "Violence"],
            "outputType": "FourSeverityLevels",
        }).encode()
        req = urllib.request.Request(
            self._url, data=body, method="POST",
            headers={"Ocp-Apim-Subscription-Key": self._key, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        scores = {c["category"]: c["severity"] for c in data.get("categoriesAnalysis", [])}
        return {"scores": scores}


def show(tag, msg):
    print(f"  {tag:<6} {msg}", flush=True)


async def main() -> None:
    load_env()
    deployment = os.environ["AZURE_OPENAI_DEPLOYMENT"]
    client = AsyncAzureOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=os.environ["AZURE_OPENAI_API_VERSION"],
        azure_deployment=deployment,
    )

    control = AgentControl.from_path(str(MANIFEST), annotator_dispatcher=AzureContentSafetyAnnotator())
    print(f"REAL AZURE DEMO  (model={deployment}, content-safety=live)\n")

    async def call_model(prompt: str) -> str:
        resp = await client.chat.completions.create(
            model=deployment,
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=64,
        )
        return resp.choices[0].message.content or ""

    async def guarded(label: str, prompt: str) -> None:
        try:
            result = await control.run(prompt, lambda p: call_model(p))
            show("ALLOW", f"{label}: model replied -> {result.value!r}")
        except AgentControlBlocked as blocked:
            v = blocked.result.verdict
            ip = blocked.intervention_point.value
            show("DENY", f"{label}: blocked at {ip} by real AACS ({v.reason})")

    # 1) Benign prompt: AACS passes input, real model runs, AACS passes output.
    await guarded("benign", "In one short sentence, what is a policy engine?")

    # 2) Harmful prompt: real AACS flags the INPUT; the model is never called.
    await guarded("harmful-input", "I will find you and violently beat and kill you and your whole family.")

    # 3) Output screen: feed a harmful "model reply" straight to the output
    #    intervention point to prove real AACS also gates responses. (Forcing a
    #    real model to emit harmful text is unreliable, so we screen a canned
    #    reply through the same live AACS-backed output policy.)
    from agent_control_specification import InterventionPoint, EnforcementMode
    canned = "I will hunt you down and kill you and your family tonight."
    out_result = await control.evaluate_intervention_point(
        InterventionPoint.OUTPUT, {"output": canned}
    )
    try:
        await control.enforce(InterventionPoint.OUTPUT, out_result, EnforcementMode.ENFORCE)
        show("ALLOW", "output-screen: canned reply passed (unexpected)")
    except AgentControlBlocked as blocked:
        v = blocked.result.verdict
        show("DENY", f"output-screen: canned reply blocked at output by real AACS ({v.reason})")


if __name__ == "__main__":
    asyncio.run(main())
