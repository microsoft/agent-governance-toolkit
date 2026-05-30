from __future__ import annotations

import re

SLUG_PATTERN = re.compile(r"[^a-z0-9_]+")
WHITESPACE_PATTERN = re.compile(r"\s+")


def slugify(value: str, *, fallback: str = "generated_policy") -> str:
    normalized = WHITESPACE_PATTERN.sub("_", value.strip().lower())
    slug = SLUG_PATTERN.sub("_", normalized).strip("_")
    return slug or fallback
