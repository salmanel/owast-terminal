import re

# Very light regex fingerprints (extend over time)
LIB_PATTERNS = [
    (re.compile(r'jquery[-\.]([0-9]+\.[0-9]+\.[0-9]+)\.js', re.I), "jQuery", "3.6.0"),
    (re.compile(r'bootstrap[-\.]([0-9]+\.[0-9]+\.[0-9]+)\.min\.css', re.I), "Bootstrap", "4.6.2"),
]

def _version_tuple(v):
    try: return tuple(map(int, v.split(".")))
    except Exception: return (0,0,0)

def run_outdated_components_checks(pages, session):
    findings = []
    for u in list(pages)[:40]:
        try:
            r = session.get(u, timeout=8, verify=False)
            if r.status_code == 200:
                body = r.text
                for rx, name, min_safe in LIB_PATTERNS:
                    for m in rx.finditer(body):
                        v = m.group(1)
                        if _version_tuple(v) < _version_tuple(min_safe):
                            findings.append({
                                "severity":"LOW",
                                "category":"OutdatedComponents",
                                "url":u, "param":"-",
                                "evidence":f"{name} version {v} detected (< {min_safe})"
                            })
        except Exception:
            pass
    return findings
