# Wire JSON schemas

These schemas describe ACS wire JSON carried between hosts, SDK adapters, and policy dispatchers. All schemas use JSON Schema draft 2020-12.

| Schema | Governs |
|---|---|
| `snapshot.schema.json` | Host supplied facts for one intervention point. |
| `policy-input.schema.json` | Canonical policy dispatcher input built by `build_policy_input`. |
| `verdict.schema.json` | Policy output normalized into the core `Verdict`. |
| `effect.schema.json` | Ordered policy target mutations used by verdict effects. |
