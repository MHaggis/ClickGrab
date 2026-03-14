"""Shared helper functions for the ClickGrab UI."""

import json
from ui.categories import FINDING_CATEGORIES


def _val(obj, key, default=None):
    """Get attribute from object or dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _count(obj, key):
    """Count items in a list field on an object or dict."""
    v = _val(obj, key, [])
    return len(v) if v else 0


def _severity_label(score: int) -> str:
    if score >= 60:
        return "Critical"
    if score >= 30:
        return "Suspicious"
    if score > 0:
        return "Low"
    return "Clean"


def _category_counts(result) -> dict:
    """Return {category_name: total_hits} for a single result."""
    out = {}
    for cat_name, cat_info in FINDING_CATEGORIES.items():
        total = sum(_count(result, f) for f, _ in cat_info["fields"])
        out[cat_name] = total
    return out


def _flatten_finding(item) -> str:
    """Convert a finding item to a compact display string."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        if "script" in item:
            return f"[score={item.get('score', '?')}] {item['script'][:200]}"
        if "Command" in item:
            risk = item.get("RiskLevel", "")
            return f"[{risk}] {item['Command'][:200]}"
        if "FullMatch" in item:
            return item["FullMatch"][:200]
        if "Base64" in item:
            decoded = item.get("Decoded", "")[:80]
            return f"{item['Base64'][:60]}...  ->  {decoded}"
        return json.dumps(item, default=str)[:200]
    # Pydantic models
    if hasattr(item, "Command"):
        risk = getattr(item, "RiskLevel", "")
        return f"[{risk}] {item.Command[:200]}"
    if hasattr(item, "FullMatch"):
        return item.FullMatch[:200]
    if hasattr(item, "Base64"):
        decoded = getattr(item, "Decoded", "")[:80]
        return f"{item.Base64[:60]}...  ->  {decoded}"
    if hasattr(item, "OriginalURL"):
        final = getattr(item, "FinalURL", "") or ""
        return f"{item.OriginalURL} -> {final}" if final else item.OriginalURL
    if hasattr(item, "ScriptURL"):
        dest = getattr(item, "DestinationURL", "")
        return f"{item.ScriptURL} -> {dest}"
    return str(item)[:200]


def _flatten_finding_full(item) -> str:
    """Full text representation for the detail view."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return json.dumps(item, indent=2, default=str)
    if hasattr(item, "model_dump"):
        return json.dumps(item.model_dump(), indent=2, default=str)
    return str(item)
