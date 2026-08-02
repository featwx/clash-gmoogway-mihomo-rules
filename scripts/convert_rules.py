#!/usr/bin/env python3
"""Convert GMOogway Shadowrocket modules to Mihomo classical rule sets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path


UPSTREAM_BASE = (
    "https://raw.githubusercontent.com/"
    "GMOogway/shadowrocket-rules/master/"
)

SOURCES = {
    "direct": {
        "source": "sr_direct_list.module",
        "output": "sr_direct.list",
        "action": "DIRECT",
        "minimum": 100_000,
    },
    "proxy": {
        "source": "sr_proxy_list.module",
        "output": "sr_proxy.list",
        "action": "PROXY",
        "minimum": 20_000,
    },
    "reject": {
        "source": "sr_reject_list.module",
        "output": "sr_reject.list",
        "action": "REJECT",
        "minimum": 150_000,
    },
}

SUPPORTED_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str, attempts: int = 3) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "GMOogway-Mihomo-Converter/1.0"},
    )
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return response.read()
        except Exception as error:  # pragma: no cover - network dependent
            last_error = error
            if attempt < attempts:
                time.sleep(attempt * 3)
    raise RuntimeError(f"failed to download {url}: {last_error}")


def read_source(source_name: str, source_dir: Path | None) -> bytes:
    if source_dir is not None:
        return (source_dir / source_name).read_bytes()
    return download(UPSTREAM_BASE + source_name)


def parse_module(data: bytes, expected_action: str) -> dict:
    text = data.decode("utf-8-sig")
    rules: list[str] = []
    seen: set[str] = set()
    skipped: list[dict] = []
    duplicate_count = 0
    type_counts: Counter[str] = Counter()
    source_headers: list[str] = []

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#!"):
            source_headers.append(line)
            continue
        if line.startswith("#") or line == "[Rule]":
            continue

        try:
            fields = next(csv.reader([line], skipinitialspace=True))
        except csv.Error as error:
            skipped.append(
                {
                    "line": line_number,
                    "type": "CSV-ERROR",
                    "reason": str(error),
                    "value": line,
                }
            )
            continue

        fields = [field.strip() for field in fields]
        rule_type = fields[0].upper() if fields else ""

        if rule_type not in SUPPORTED_TYPES:
            skipped.append(
                {
                    "line": line_number,
                    "type": rule_type or "EMPTY",
                    "reason": "unsupported by Mihomo classical rules",
                    "value": line,
                }
            )
            continue

        try:
            action_index = fields.index(expected_action, 2)
        except ValueError as error:
            raise ValueError(
                f"line {line_number}: expected action {expected_action}: {line}"
            ) from error

        converted_fields = fields[:action_index] + fields[action_index + 1 :]
        if len(converted_fields) < 2 or not converted_fields[1]:
            raise ValueError(f"line {line_number}: invalid rule: {line}")

        if rule_type in IP_TYPES and "no-resolve" not in converted_fields[2:]:
            converted_fields.append("no-resolve")

        converted = ",".join(converted_fields)
        if converted in seen:
            duplicate_count += 1
            continue

        seen.add(converted)
        rules.append(converted)
        type_counts[rule_type] += 1

    return {
        "rules": rules,
        "skipped": skipped,
        "duplicates": duplicate_count,
        "type_counts": dict(sorted(type_counts.items())),
        "source_headers": source_headers,
    }


def render_rule_set(source_url: str, source_sha: str, parsed: dict) -> bytes:
    header = [
        "# Mihomo classical rule-provider",
        f"# Upstream: {source_url}",
        f"# Upstream-SHA256: {source_sha}",
        f"# Converted-Rules: {len(parsed['rules'])}",
        f"# Skipped-Unsupported: {len(parsed['skipped'])}",
    ]
    for source_header in parsed["source_headers"]:
        header.append(f"# Upstream-Metadata: {source_header[2:]}")
    return ("\n".join(header + parsed["rules"]) + "\n").encode("utf-8")


def write_if_changed(path: Path, data: bytes) -> bool:
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-dir",
        type=Path,
        help="Use a local checkout instead of downloading the upstream files.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("rules"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()

    manifest: dict[str, dict] = {}
    skipped_report: dict[str, dict] = {}

    for key, definition in SOURCES.items():
        source_name = definition["source"]
        source_url = UPSTREAM_BASE + source_name
        source_data = read_source(source_name, args.source_dir)
        parsed = parse_module(source_data, definition["action"])

        if len(parsed["rules"]) < definition["minimum"]:
            raise RuntimeError(
                f"{key}: only {len(parsed['rules'])} converted rules; "
                f"expected at least {definition['minimum']}"
            )

        source_sha = sha256(source_data)
        output_data = render_rule_set(source_url, source_sha, parsed)
        output_path = args.output_dir / definition["output"]
        write_if_changed(output_path, output_data)

        skipped_counts = Counter(item["type"] for item in parsed["skipped"])
        manifest[key] = {
            "source": source_url,
            "source_sha256": source_sha,
            "output": output_path.as_posix(),
            "output_sha256": sha256(output_data),
            "converted_rules": len(parsed["rules"]),
            "duplicates_removed": parsed["duplicates"],
            "skipped_unsupported": len(parsed["skipped"]),
            "skipped_types": dict(sorted(skipped_counts.items())),
            "rule_types": parsed["type_counts"],
        }
        skipped_report[key] = {
            "count": len(parsed["skipped"]),
            "types": dict(sorted(skipped_counts.items())),
            "items": parsed["skipped"],
        }

    manifest_data = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    skipped_data = (
        json.dumps(skipped_report, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    write_if_changed(args.output_dir / "manifest.json", manifest_data)
    write_if_changed(args.report_dir / "skipped.json", skipped_data)

    json.dump(manifest, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
