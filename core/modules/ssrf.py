# Safe SSRF: we do NOT actually reach cloud metadata.
# We only flag suspicious parameters and (optionally) try a closed local port to see if server-side fetch happens quickly.
import time, requests

def run_ssrf_checks(pages, session, cfg):
    findings = []
    params = cfg.get("params", ["url","uri","dest","u","target","feed","image","load","fetch"])
    harmless = cfg.get("harmless_oracles", ["http://127.0.0.1:81"])

    sample = list(pages)[:30]
    for base in sample:
        for p in params:
            # Heuristic: parameter exists in URL template
            if (f"{p}=" in base) or ("?" in base):
                # Try a closed local port to detect server-side fetch timing/behavior
                for o in harmless:
                    try:
                        sep = "&" if "?" in base else "?"
                        u = f"{base}{sep}{p}={requests.utils.quote(o, safe='')}"
                        t0 = time.time()
                        r = session.get(u, timeout=6, verify=False)
                        dt = time.time() - t0
                        # If app attempted server-side fetch we may see specific error messages or longer latency
                        if r.status_code in (200, 302, 500) and ("connection refused" in r.text.lower() or dt > 1.8):
                            findings.append({
                                "severity":"MEDIUM",
                                "category":"SSRF",
                                "url":u, "param":p,
                                "evidence":f"Suspicious server-side fetch behavior (dt={dt:.1f}s)"
                            })
                            break
                    except Exception:
                        pass
    return findings
