# Policy model

Rules are ordered by descending priority then rule ID. Conditions use only `all`, `any`, `not`, and field comparisons (`eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`, `exists`, `not_exists`). They are data, not Python expressions. Invalid conditions produce `UNKNOWN` with `EVALUATION_ERROR` and cannot allow an action.
