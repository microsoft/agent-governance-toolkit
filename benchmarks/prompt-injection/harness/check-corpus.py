#!/usr/bin/env python3
"""Validate prompt-injection fixture corpus rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path


MAX_LEAK_EXAMPLES = 25
NEAR_DUPLICATE_NGRAM = 7
NEAR_DUPLICATE_THRESHOLD = 0.92
SIMHASH_BAND_BITS = 16


REQUIRED = {
    "id",
    "text",
    "source_type",
    "trust_level",
    "attack_class",
    "risk_level",
    "expected_action",
    "contains_sensitive_sink",
    "requires_tool_call",
    "bypass_class",
    "group_id",
    "split",
    "family_id",
    "generator_id",
    "benign_subclass",
    "label_source",
    "created_round",
}

ALLOWED_SPLITS = {"exemplar_bank", "validation", "test"}
ALLOWED_ACTIONS = {"allow", "quarantine", "block", "require_approval", "log_only"}
ALLOWED_BYPASS_CLASSES = {
    "chunked_leet",
    "compact_leet",
    "compact_plain",
    "diacritics",
    "encoding",
    "homoglyph",
    "leet_letter_spaced",
    "leet_spacing",
    "letter_spaced",
    "multilingual",
    "none",
    "plain",
    "rot13",
    "separator_spaced",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_lf_normalized(path: Path) -> str:
    raw = path.read_bytes()
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def normalized_alnum(text: str) -> str:
    return "".join(ch for ch in normalize_text(text) if ch.isalnum())


def normalized_ngrams(text: str, n: int = NEAR_DUPLICATE_NGRAM) -> set[str]:
    compact = normalized_alnum(text)
    if not compact:
        return set()
    if len(compact) <= n:
        return {compact}
    return {compact[i : i + n] for i in range(0, len(compact) - n + 1)}


def simhash64(grams: set[str]) -> int:
    if not grams:
        return 0
    weights = [0] * 64
    for gram in grams:
        value = int(sha256_text(gram)[:16], 16)
        for bit in range(64):
            weights[bit] += 1 if value & (1 << bit) else -1
    sig = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            sig |= 1 << bit
    return sig


def simhash_bands(sig: int) -> list[tuple[int, int]]:
    mask = (1 << SIMHASH_BAND_BITS) - 1
    return [(band, (sig >> (band * SIMHASH_BAND_BITS)) & mask) for band in range(64 // SIMHASH_BAND_BITS)]


def row_ref(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "split": row.get("split"),
        "family_id": row.get("family_id"),
        "group_id": row.get("group_id"),
        "generator_id": row.get("generator_id"),
        "attack_class": row.get("attack_class"),
        "benign_subclass": row.get("benign_subclass"),
        "bypass_class": row.get("bypass_class"),
    }


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def normalized_text_check(rows: list[dict]) -> dict:
    by_hash: dict[str, list[dict]] = defaultdict(list)
    records = []
    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)

    for idx, row in enumerate(rows):
        normalized = normalize_text(str(row.get("text", "")))
        normalized_hash = sha256_text(normalized)
        grams = normalized_ngrams(str(row.get("text", "")))
        sig = simhash64(grams)
        by_hash[normalized_hash].append(row)
        records.append({"row": row, "grams": grams, "simhash": sig})
        for band in simhash_bands(sig):
            buckets[band].append(idx)

    exact_examples = []
    exact_count = 0
    for normalized_hash, hashed_rows in sorted(by_hash.items()):
        splits = {row.get("split") for row in hashed_rows}
        families = {row.get("family_id") for row in hashed_rows}
        if len(splits) > 1 and len(families) > 1:
            exact_count += 1
            if len(exact_examples) < MAX_LEAK_EXAMPLES:
                exact_examples.append(
                    {
                        "normalized_sha256": normalized_hash,
                        "rows": [row_ref(row) for row in hashed_rows],
                    }
                )

    near_examples = []
    near_pairs: set[tuple[int, int]] = set()
    near_count = 0
    for bucket_idxs in buckets.values():
        for pos, left_idx in enumerate(bucket_idxs):
            left = records[left_idx]
            left_row = left["row"]
            for right_idx in bucket_idxs[pos + 1 :]:
                pair = (left_idx, right_idx) if left_idx < right_idx else (right_idx, left_idx)
                if pair in near_pairs:
                    continue
                right = records[right_idx]
                right_row = right["row"]
                if left_row.get("split") == right_row.get("split"):
                    continue
                if left_row.get("family_id") == right_row.get("family_id"):
                    continue
                score = jaccard(left["grams"], right["grams"])
                if score < NEAR_DUPLICATE_THRESHOLD:
                    continue
                near_pairs.add(pair)
                near_count += 1
                if len(near_examples) < MAX_LEAK_EXAMPLES:
                    near_examples.append(
                        {
                            "similarity": round(score, 6),
                            "left": row_ref(left_row),
                            "right": row_ref(right_row),
                        }
                    )

    return {
        "normalized_hash_count": len(by_hash),
        "exact_normalized_hash_cross_split_count": exact_count,
        "exact_normalized_hash_cross_split_examples": exact_examples,
        "near_duplicate_cross_split_count": near_count,
        "near_duplicate_threshold": NEAR_DUPLICATE_THRESHOLD,
        "near_duplicate_ngram": NEAR_DUPLICATE_NGRAM,
        "near_duplicate_examples": near_examples,
        "passed": exact_count == 0 and near_count == 0,
    }


def duplicate_check_from_normalized(text_check: dict) -> dict:
    return {
        "normalized_hash_count": text_check["normalized_hash_count"],
        "exact_cross_split_duplicate_count": text_check["exact_normalized_hash_cross_split_count"],
        "exact_cross_split_duplicates": [
            {
                "normalized_text_sha256": example["normalized_sha256"],
                "rows": example["rows"],
            }
            for example in text_check["exact_normalized_hash_cross_split_examples"]
        ],
        "near_duplicate_cross_split_count": text_check["near_duplicate_cross_split_count"],
        "near_duplicate_ngram": text_check["near_duplicate_ngram"],
        "near_duplicate_threshold": text_check["near_duplicate_threshold"],
        "near_cross_split_duplicates": text_check["near_duplicate_examples"],
        "passed": text_check["passed"],
    }


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            rows.append(row)
    return rows


def count_by(rows: list[dict], key: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get(key, "")) for row in rows).items()))


def split_label_coverage(rows: list[dict]) -> dict:
    coverage = {split: {"attack": 0, "benign": 0} for split in sorted(ALLOWED_SPLITS)}
    for row in rows:
        split = str(row.get("split"))
        if split not in coverage:
            continue
        label = "benign" if row.get("attack_class") == "benign" else "attack"
        coverage[split][label] += 1
    missing = [
        {"split": split, "missing": label}
        for split, counts in coverage.items()
        for label, count in counts.items()
        if count == 0
    ]
    return {
        "by_split": coverage,
        "missing": missing,
        "passed": not missing,
    }


def validate(rows: list[dict], manifest: dict | None, corpus_path: Path) -> tuple[bool, list[str], dict]:
    errors: list[str] = []
    ids: set[str] = set()
    family_splits: dict[str, set[str]] = defaultdict(set)
    group_splits: dict[str, set[str]] = defaultdict(set)

    for idx, row in enumerate(rows, 1):
        missing = REQUIRED - set(row)
        if missing:
            errors.append(f"row {idx} missing fields: {sorted(missing)}")
        row_id = row.get("id")
        if row_id in ids:
            errors.append(f"duplicate id: {row_id}")
        ids.add(row_id)

        split = row.get("split")
        if split not in ALLOWED_SPLITS:
            errors.append(f"{row_id}: invalid split {split!r}")
        action = row.get("expected_action")
        if action not in ALLOWED_ACTIONS:
            errors.append(f"{row_id}: invalid expected_action {action!r}")
        bypass_class = row.get("bypass_class")
        if bypass_class not in ALLOWED_BYPASS_CLASSES:
            errors.append(f"{row_id}: invalid bypass_class {bypass_class!r}")
        if row.get("attack_class") == "benign" and row.get("expected_action") != "allow":
            errors.append(f"{row_id}: benign row expected_action must be allow")
        if row.get("attack_class") != "benign" and row.get("benign_subclass") != "not_applicable":
            errors.append(f"{row_id}: attack row benign_subclass must be not_applicable")

        family_splits[str(row.get("family_id"))].add(str(split))
        group_splits[str(row.get("group_id"))].add(str(split))

    family_leaks = sorted(k for k, v in family_splits.items() if len(v) > 1)
    group_leaks = sorted(k for k, v in group_splits.items() if len(v) > 1)
    if family_leaks:
        errors.append(f"family split leaks: {family_leaks[:10]}")
    if group_leaks:
        errors.append(f"group split leaks: {group_leaks[:10]}")

    text_check = normalized_text_check(rows)
    summary = {
        "row_count": len(rows),
        "counts": {
            "split": count_by(rows, "split"),
            "attack_class": count_by(rows, "attack_class"),
            "bypass_class": count_by(rows, "bypass_class"),
            "benign_subclass": count_by(rows, "benign_subclass"),
            "source_type": count_by(rows, "source_type"),
            "trust_level": count_by(rows, "trust_level"),
            "expected_action": count_by(rows, "expected_action"),
        },
        "leakage_check": {
            "family_count": len(family_splits),
            "group_count": len(group_splits),
            "family_split_leaks": family_leaks,
            "group_split_leaks": group_leaks,
            "passed": not family_leaks and not group_leaks,
        },
        "normalized_text_check": text_check,
        "duplicate_check": duplicate_check_from_normalized(text_check),
        "split_label_coverage_check": split_label_coverage(rows),
    }

    if summary["normalized_text_check"].get("passed") is not True:
        errors.append("normalized_text_check.passed is not true")
    if summary["split_label_coverage_check"].get("passed") is not True:
        errors.append("split_label_coverage_check.passed is not true")

    if manifest:
        if manifest.get("row_count") != len(rows):
            errors.append(f"manifest row_count mismatch: {manifest.get('row_count')} != {len(rows)}")
        expected_hash = manifest.get("output_sha256")
        actual_hash = sha256(corpus_path)
        normalized_hash = None
        hash_mode = "byte_exact"
        if expected_hash != actual_hash:
            normalized_hash = sha256_lf_normalized(corpus_path)
            hash_mode = "lf_normalized" if expected_hash == normalized_hash else "mismatch"
        summary["hash_check"] = {
            "manifest_output_sha256": expected_hash,
            "worktree_output_sha256": actual_hash,
            "lf_normalized_output_sha256": normalized_hash,
            "mode": hash_mode,
            "passed": hash_mode in {"byte_exact", "lf_normalized"},
        }
        if summary["hash_check"]["passed"] is not True:
            errors.append(f"manifest output_sha256 mismatch: {expected_hash} != {actual_hash}")
        manifest_leakage = manifest.get("leakage_check", {})
        if manifest_leakage.get("passed") is not True:
            errors.append("manifest leakage_check.passed is not true")
        if manifest.get("normalized_text_check") != summary["normalized_text_check"]:
            errors.append("manifest normalized_text_check mismatch")
        if manifest.get("duplicate_check") != summary["duplicate_check"]:
            errors.append("manifest duplicate_check mismatch")
        if manifest.get("split_label_coverage_check") != summary["split_label_coverage_check"]:
            errors.append("manifest split_label_coverage_check mismatch")
        for key, counts in summary["counts"].items():
            if manifest.get("counts", {}).get(key) != counts:
                errors.append(f"manifest counts mismatch for {key}")

    return not errors, errors, summary


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=Path)
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--summary-json", type=Path)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    rows = load_jsonl(args.corpus)
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    ok, errors, summary = validate(rows, manifest, args.corpus)
    if args.summary_json:
        with args.summary_json.open("w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not ok:
        for err in errors:
            print(f"ERROR: {err}")
        return 1
    print("prompt-injection-corpus-check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
