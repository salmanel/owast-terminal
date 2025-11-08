from __future__ import annotations
from pathlib import Path
import json

DEFAULTS = {
    "xss_reflected": [
        "<svg onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
    ],
    "sqli_basic": [
        "' OR '1'='1",
        "' UNION SELECT 1--",
        "\" OR 1=1--",
    ],
}

class StaticPayloadProvider:
    """
    Returns payloads from config if present, otherwise defaults.
    Optionally can read newline-delimited payload files (txt/json list)
    placed under third_party/* and referenced in config as:
      payload_files:
        xss_reflected: "third_party/xss-payload-list/Intruder/payloads.txt"
        sqli_basic: "third_party/sql-injection-payload-list/Intruder/exploit/some.txt"
    """
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    def _load_file_list(self, path: str) -> list[str]:
        p = Path(path)
        if not p.exists():
            return []
        try:
            if p.suffix.lower() == ".json":
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return [str(x).strip() for x in data if str(x).strip()]
                return []
            # assume newline-delimited text
            return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except Exception:
            return []

    def get_payloads(self) -> dict:
        cfg_payloads = (self.cfg.get("payloads") or {}).copy()
        for key, default_list in DEFAULTS.items():
            if key not in cfg_payloads:
                cfg_payloads[key] = default_list[:]

        # Optional external files
        files = (self.cfg.get("payload_files") or {})
        for key, file_path in files.items():
            extra = self._load_file_list(file_path)
            if extra:
                base = cfg_payloads.get(key, [])
                # dedupe while keeping order
                seen = set()
                merged = []
                for item in list(base) + list(extra):
                    if item not in seen:
                        merged.append(item)
                        seen.add(item)
                cfg_payloads[key] = merged
        return cfg_payloads
