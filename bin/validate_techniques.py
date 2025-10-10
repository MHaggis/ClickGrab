#!/usr/bin/env python3
"""Basic schema validation for technique definition files."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

import yaml


REQUIRED_TOP_LEVEL = {"name", "platform", "presentation", "lures"}
REQUIRED_LURE_FIELDS = {"nickname", "steps"}


def iter_technique_files(root: Path) -> Iterable[Path]:
    techniques_dir = root / "techniques"
    if not techniques_dir.exists():
        raise SystemExit("techniques directory not found")
    yield from sorted(techniques_dir.glob("*.yml"))


def validate_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        return [f"{path.name}: failed to parse YAML ({exc})"]

    if not isinstance(data, dict):
        return [f"{path.name}: top-level YAML document must be a mapping"]

    missing = REQUIRED_TOP_LEVEL - data.keys()
    if missing:
        errors.append(f"{path.name}: missing required keys {sorted(missing)}")

    lures = data.get("lures", [])
    if not isinstance(lures, list) or not lures:
        errors.append(f"{path.name}: lures must be a non-empty list")
    else:
        for idx, lure in enumerate(lures, start=1):
            if not isinstance(lure, dict):
                errors.append(f"{path.name} lure #{idx}: must be a mapping")
                continue
            missing_lure = REQUIRED_LURE_FIELDS - lure.keys()
            if missing_lure:
                errors.append(
                    f"{path.name} lure '{lure.get('nickname', f'#${idx}')}' missing keys {sorted(missing_lure)}"
                )
            steps = lure.get("steps")
            if not isinstance(steps, list) or not all(isinstance(step, str) for step in steps):
                errors.append(
                    f"{path.name} lure '{lure.get('nickname', f'#${idx}')}' has invalid steps (must be list of strings)"
                )

    return errors


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    all_errors: list[str] = []
    for technique_file in iter_technique_files(root):
        all_errors.extend(validate_file(technique_file))

    if all_errors:
        print("Technique validation failed:")
        for error in all_errors:
            print(f" - {error}")
        return 1

    print("All technique files validated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

