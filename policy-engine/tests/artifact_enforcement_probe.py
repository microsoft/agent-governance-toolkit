"""Drive real ACS enforcement cases through the shipped native artifact.

This deliberately avoids every Rust and .NET test harness. It dlopen()s the
release `.so` and calls the C ABI the way a host integrator would, so what is
under test is the artifact that actually ships, not a build of the sources.
"""

import ctypes
import json
import subprocess
import sys
from pathlib import Path

LIB = Path(sys.argv[1]).resolve()
OPA = Path.home() / ".local/bin/opa"

lib = ctypes.CDLL(str(LIB))
lib.acs_builder_from_yaml.restype = ctypes.c_void_p
lib.acs_builder_from_yaml.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
lib.acs_builder_enable_default_policy_dispatcher.restype = ctypes.c_int
lib.acs_builder_enable_default_policy_dispatcher.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
lib.acs_builder_enable_default_annotator_dispatcher.restype = ctypes.c_int
lib.acs_builder_enable_default_annotator_dispatcher.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
lib.acs_builder_build.restype = ctypes.c_void_p
lib.acs_builder_build.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
lib.acs_runtime_evaluate.restype = ctypes.c_void_p
lib.acs_runtime_evaluate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
lib.acs_runtime_policy_labels.restype = ctypes.c_void_p
lib.acs_runtime_policy_labels.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
lib.acs_free_string.argtypes = [ctypes.c_void_p]
lib.acs_runtime_free.argtypes = [ctypes.c_void_p]

MANIFEST = """
agent_control_specification_version: 0.4.0-alpha.1
metadata:
  name: artifact_enforcement_probe
policies:
  p:
    type: rego
    query: data.probe.verdict
    bundle: BUNDLE_DIR
intervention_points:
  input:
    policy_target: $.input.text
    policy:
      id: p
"""

REGO = """
package probe
import rego.v1

default verdict := {"decision": "allow"}

# A plain refusal.
verdict := {"decision": "deny", "reason": "blocked_topic"} if {
    contains(input.policy_target.value, "forbidden")
}

# The warn intent: the engine must normalize this to allow + warnings[].
else := {"decision": "warn", "reason": "pii_detected"} if {
    contains(input.policy_target.value, "ssn")
}

# The escalate intent: the engine must normalize this to a liftable deny.
else := {"decision": "escalate", "reason": "needs_review"} if {
    contains(input.policy_target.value, "wire")
}

# The only value-changing decision.
else := {
    "decision": "transform",
    "reason": "redacted",
    "transform": {"path": "$target", "value": "[REDACTED]"},
} if {
    contains(input.policy_target.value, "secret")
}
"""


def take(ptr):
    if not ptr:
        return None
    out = ctypes.cast(ptr, ctypes.c_char_p).value.decode()
    lib.acs_free_string(ptr)
    return out


def build_runtime(tmp: Path):
    bundle = tmp / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "probe.rego").write_text(REGO)
    subprocess.run(
        [str(OPA), "build", "-t", "wasm", "-o", str(tmp / "b.tar.gz"), str(bundle)],
        capture_output=True,
    )
    manifest = MANIFEST.replace("BUNDLE_DIR", str(bundle))
    err = ctypes.c_char_p()
    builder = lib.acs_builder_from_yaml(manifest.encode(), ctypes.byref(err))
    if not builder:
        raise SystemExit(f"builder failed: {err.value}")
    if lib.acs_builder_enable_default_policy_dispatcher(builder, ctypes.byref(err)) != 0:
        raise SystemExit(f"policy dispatcher failed: {err.value}")
    runtime = lib.acs_builder_build(builder, ctypes.byref(err))
    if not runtime:
        raise SystemExit(f"build failed: {err.value}")
    return runtime


def evaluate(runtime, text, mode="enforce"):
    request = json.dumps(
        {
            "intervention_point": "input",
            "mode": mode,
            "snapshot": {"input": {"text": text}},
        }
    )
    err = ctypes.c_char_p()
    raw = take(lib.acs_runtime_evaluate(runtime, request.encode(), ctypes.byref(err)))
    if raw is None:
        raise SystemExit(f"evaluate failed: {err.value}")
    return json.loads(raw)


CASES = [
    # (input, expected decision, must-be-liftable, must-carry-warnings, expected effective value)
    ("hello world", "allow", False, False, "hello world"),
    ("this is forbidden", "deny", False, False, None),
    ("my ssn is 123", "allow", False, True, "my ssn is 123"),
    ("please wire funds", "deny", True, False, None),
    ("the secret token", "transform", False, False, "[REDACTED]"),
]


def main():
    import tempfile

    failures = []
    with tempfile.TemporaryDirectory() as td:
        runtime = build_runtime(Path(td))

        labels = json.loads(take(lib.acs_runtime_policy_labels(runtime, ctypes.byref(ctypes.c_char_p()))))
        if labels.get("input", {}).get("policy_id") != "p":
            failures.append(f"policy_labels wrong: {labels}")

        for text, want_decision, want_liftable, want_warnings, want_value in CASES:
            r = evaluate(runtime, text)
            v = r["verdict"]
            got = v["decision"]
            liftable = v.get("approval") is not None
            warned = bool(v.get("warnings"))
            applied = r.get("transformed_policy_target")
            effective = applied if applied is not None else text

            ok = got == want_decision and liftable == want_liftable and warned == want_warnings
            if want_value is not None:
                ok = ok and effective == want_value
            status = "PASS" if ok else "FAIL"
            if not ok:
                failures.append(
                    f"{text!r}: got decision={got} liftable={liftable} "
                    f"warnings={warned} effective={effective!r}"
                )
            print(
                f"  {status}  {text!r:24} -> {got:9} "
                f"liftable={str(liftable):5} warnings={str(warned):5} effective={effective!r}"
            )

        # evaluate_only must compute the same verdict but never apply the transform.
        shadow = evaluate(runtime, "the secret token", mode="evaluate_only")
        same_decision = shadow["verdict"]["decision"] == "transform"
        not_applied = shadow.get("transformed_policy_target") is None
        ok = same_decision and not_applied
        print(
            f"  {'PASS' if ok else 'FAIL'}  evaluate_only            -> transform computed="
            f"{same_decision}, applied={not not_applied} (must be False)"
        )
        if not ok:
            failures.append(f"evaluate_only wrong: {shadow}")

        # A malformed envelope must fail closed in the host namespace.
        err = ctypes.c_char_p()
        bad = json.loads(
            take(lib.acs_runtime_evaluate(runtime, b'{"snapshot": {}}', ctypes.byref(err)))
        )
        reason = bad["verdict"].get("reason")
        ok = bad["verdict"]["decision"] == "deny" and reason == "host_error:context_invalid"
        print(f"  {'PASS' if ok else 'FAIL'}  malformed envelope       -> deny reason={reason}")
        if not ok:
            failures.append(f"malformed envelope wrong: {bad}")

        lib.acs_runtime_free(runtime)

    print()
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all enforcement cases behaved as expected against the shipped artifact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
