#!/usr/bin/env python3
"""Validate every deployments/<env>/config.yaml against schemas/deployment.schema.json.

Usage:
    python3 scripts/validate-deployments.py

Requires: pyyaml, jsonschema  (pip install pyyaml jsonschema rfc3339-validator)
Exits non-zero if any config fails. Intended for local use and CI.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
    from jsonschema import Draft202012Validator
    from jsonschema import FormatChecker
except ImportError as exc:  # pragma: no cover - dependency hint
    sys.exit(
        f"missing dependency: {exc.name}. "
        "Install with: pip install pyyaml jsonschema rfc3339-validator"
    )

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "deployment.schema.json"
CONFIG_GLOB = "deployments/*/config.yaml"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    configs = sorted(ROOT.glob(CONFIG_GLOB))
    if not configs:
        print(f"no configs matched {CONFIG_GLOB}", file=sys.stderr)
        return 1

    failed = 0
    for config in configs:
        rel = config.relative_to(ROOT)
        data = yaml.safe_load(config.read_text())
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for err in errors:
                location = "/".join(str(p) for p in err.path) or "<root>"
                print(f"  - {location}: {err.message}")
        else:
            print(f"PASS {rel}")

    print(f"\n{len(configs) - failed}/{len(configs)} configs valid")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
