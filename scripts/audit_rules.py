#!/usr/bin/env python3
"""Audit converted rule sets and document cross-list priority conflicts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RULE_FILES = {
    "direct": "sr_direct.list",
    "proxy": "sr_proxy.list",
    "reject": "sr_reject.list",
}


def load_rules(path: Path) -> dict:
    rules: list[str] = []
    by_type: dict[str, set[str]] = {}
    errors: list[str] = []

    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 2:
            errors.append(f"line {number}: too few fields: {line}")
            continue
        rule_type = fields[0]
        value = fields[1].lower().rstrip(".")
        if fields[-1] in {"DIRECT", "PROXY", "REJECT"}:
            errors.append(f"line {number}: policy was not stripped: {line}")
        if rule_type in {"IP-CIDR", "IP-CIDR6"} and "no-resolve" not in fields[2:]:
            errors.append(f"line {number}: IP rule lacks no-resolve: {line}")
        rules.append(line)
        by_type.setdefault(rule_type, set()).add(value)

    return {"rules": rules, "by_type": by_type, "errors": errors}


def domain_values(loaded: dict) -> set[str]:
    return loaded["by_type"].get("DOMAIN", set()) | loaded["by_type"].get(
        "DOMAIN-SUFFIX", set()
    )


def suffix_coverage(values: set[str], suffixes: set[str]) -> list[tuple[str, str]]:
    covered: list[tuple[str, str]] = []
    for value in sorted(values):
        labels = value.split(".")
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            if suffix in suffixes:
                covered.append((value, suffix))
                break
    return covered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-dir", type=Path, default=Path("rules"))
    parser.add_argument(
        "--output", type=Path, default=Path("reports") / "audit.json"
    )
    args = parser.parse_args()

    loaded = {
        name: load_rules(args.rules_dir / filename)
        for name, filename in RULE_FILES.items()
    }
    errors = [
        f"{name}: {error}"
        for name, result in loaded.items()
        for error in result["errors"]
    ]

    comparisons: dict[str, dict] = {}
    for first, second in (
        ("direct", "proxy"),
        ("direct", "reject"),
        ("proxy", "reject"),
    ):
        first_values = domain_values(loaded[first])
        second_values = domain_values(loaded[second])
        exact = sorted(first_values & second_values)
        first_by_second = suffix_coverage(
            first_values, loaded[second]["by_type"].get("DOMAIN-SUFFIX", set())
        )
        second_by_first = suffix_coverage(
            second_values, loaded[first]["by_type"].get("DOMAIN-SUFFIX", set())
        )
        comparisons[f"{first}_vs_{second}"] = {
            "exact_domain_value_conflicts": len(exact),
            "exact_samples": exact[:20],
            f"{first}_covered_by_{second}_suffix": len(first_by_second),
            f"{first}_covered_samples": first_by_second[:20],
            f"{second}_covered_by_{first}_suffix": len(second_by_first),
            f"{second}_covered_samples": second_by_first[:20],
        }

    report = {
        "valid": not errors,
        "errors": errors,
        "recommended_rule_order": ["reject", "proxy", "direct"],
        "priority_reason": (
            "Reject should win over tracking/ad overlaps; explicit proxy exceptions "
            "should win over broad direct suffixes such as country TLD rules."
        ),
        "sets": {
            name: {
                "rules": len(result["rules"]),
                "types": {
                    rule_type: len(values)
                    for rule_type, values in sorted(result["by_type"].items())
                },
            }
            for name, result in loaded.items()
        },
        "comparisons": comparisons,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
