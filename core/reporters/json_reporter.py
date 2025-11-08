# core/reporters/json_reporter.py
from __future__ import annotations
import json
from dataclasses import is_dataclass, asdict
from typing import Any

def _to_serializable(obj: Any) -> Any:
    """Safely convert dataclasses and other objects to JSON-serializable."""
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    return obj

def write_json_report(result: Any, path: str) -> str:
    """
    Write the scan result to JSON.
    `result` can be a dataclass (e.g., ScanResult) or a plain dict.
    Returns the written file path.
    """
    data = _to_serializable(result)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path
