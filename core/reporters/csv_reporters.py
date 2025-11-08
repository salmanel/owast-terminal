from __future__ import annotations
import csv

def save_csv_report(result, out_base: str) -> str:
    csv_path = out_base + ".csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity","category","url","param","evidence"])
        for it in result.findings:
            w.writerow([it.severity, it.category, it.url, it.param, it.evidence])
    return csv_path
