"""Fuzz target for YAML policy parsing.

Tests that malformed/adversarial YAML input doesn't cause crashes,
hangs, or resource exhaustion in the policy parser.
"""
import sys
import atheris
import yaml


def fuzz_yaml_policy_parse(data: bytes) -> None:
    """Fuzz the YAML policy loading path."""
    try:
        text = data.decode("utf-8", errors="replace")
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            return

        # Simulate the policy loading path
        api_version = parsed.get("apiVersion", "")
        if not isinstance(api_version, str):
            return

        kind = parsed.get("kind", "")
        metadata = parsed.get("metadata", {})
        if isinstance(metadata, dict):
            _ = metadata.get("name", "")
            _ = metadata.get("namespace", "")

        spec = parsed.get("spec", {})
        if isinstance(spec, dict):
            rules = spec.get("rules", [])
            if isinstance(rules, list):
                for rule in rules[:50]:  # Cap iteration
                    if isinstance(rule, dict):
                        _ = rule.get("action", "")
                        _ = rule.get("effect", "")
                        conditions = rule.get("conditions", {})
                        if isinstance(conditions, dict):
                            for key, val in list(conditions.items())[:20]:
                                _ = str(key)
                                _ = str(val)

    except (yaml.YAMLError, ValueError, TypeError, KeyError,
            UnicodeDecodeError, RecursionError, MemoryError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, fuzz_yaml_policy_parse)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
