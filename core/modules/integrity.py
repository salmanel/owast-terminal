import re

def run_integrity_checks(pages, session):
    findings = []
    # External scripts without SRI (subresource integrity) – basic heuristic
    for u in list(pages)[:40]:
        try:
            r = session.get(u, timeout=8, verify=False)
            if r.status_code == 200 and "<script" in r.text.lower():
                for m in re.finditer(r'<script[^>]+src=["\'](http[^"\']+)["\']', r.text, flags=re.I):
                    tag = m.group(0)
                    if 'integrity=' not in tag.lower():
                        findings.append({
                            "severity":"LOW",
                            "category":"Integrity",
                            "url":u, "param":"-",
                            "evidence":"External <script> without SRI attribute"
                        })
        except Exception:
            pass
    return findings
