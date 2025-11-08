#!/usr/bin/env python3
"""
Incremental JSONL reporter

Writes each finding as a single JSON line as soon as it's produced.
Writes a small meta JSON alongside the JSONL file for live progress.

Files created:
 - reports/<scan_id>.findings.jsonl
 - reports/<scan_id>.meta.json
"""

from __future__ import annotations

import os
import json
import time
import threading
from pathlib import Path
from dataclasses import asdict
from typing import Optional, Dict, Any

class IncrementalJSONLReporter:
    def __init__(self, out_dir: Path, scan_id: str):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = scan_id

        self.jsonl_path = self.out_dir / f"{scan_id}.findings.jsonl"
        self.meta_path = self.out_dir / f"{scan_id}.meta.json"

        # create/truncate JSONL file
        self._fh = open(self.jsonl_path, "w", encoding="utf-8")
        self._lock = threading.Lock()

        # initial meta
        self._meta: Dict[str, Any] = {
            "scan_id": scan_id,
            "target": None,
            "started_at": time.time(),
            "finished_at": None,
            "pages": 0,
            "forms": 0,
            "totals": {"HIGH": 0, "MEDIUM": 0, "INFO": 0},
        }
        # write initial meta
        self._flush_meta()

    def set_target(self, target: str):
        with self._lock:
            self._meta["target"] = target
            self._flush_meta()

    def add_finding(self, finding) -> None:
        """
        `finding` may be a dataclass or a mapping; we will convert to dict.
        """
        try:
            row = asdict(finding)
        except Exception:
            # fallback : assume mapping-like
            row = dict(finding)

        sev = (row.get("severity") or "INFO").upper()
        if sev not in ("HIGH", "MEDIUM", "INFO", "LOW"):
            sev = "INFO"

        with self._lock:
            self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            # flush & fsync for durability
            self._fh.flush()
            try:
                os.fsync(self._fh.fileno())
            except Exception:
                # not fatal — continue quietly
                pass

            # increment totals
            if sev == "HIGH":
                self._meta["totals"]["HIGH"] += 1
            elif sev == "MEDIUM":
                self._meta["totals"]["MEDIUM"] += 1
            else:
                self._meta["totals"]["INFO"] += 1

            # update meta on each add for live viewing
            self._flush_meta()

    def update_progress(self, pages: int, forms: int):
        with self._lock:
            self._meta["pages"] = int(pages)
            self._meta["forms"] = int(forms)
            self._flush_meta()

    def close(self):
        with self._lock:
            self._meta["finished_at"] = time.time()
            self._flush_meta()
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            except Exception:
                pass
            finally:
                try:
                    self._fh.close()
                except Exception:
                    pass

    def _flush_meta(self):
        tmp = self.meta_path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(self._meta, indent=2), encoding="utf-8")
            # atomic replace
            os.replace(tmp, self.meta_path)
        except Exception:
            # best-effort: try direct write
            try:
                self.meta_path.write_text(json.dumps(self._meta, indent=2), encoding="utf-8")
            except Exception:
                pass
