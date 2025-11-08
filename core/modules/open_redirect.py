from urllib.parse import urlparse, urljoin, urlencode
import re, itertools
import requests

def run_open_redirect_checks(pages, session, cfg):
    findings = []
    params = cfg.get("params", ["next","url","redirect","return","dest","path","continue"])
    sinks  = cfg.get("sinks", ["//evil.tld"])

    test_pairs = list(itertools.product(params, sinks))
    sample = list(pages)[:30]  # cap

    for base in sample:
        for p, sink in test_pairs:
            try:
                # send as GET param
                u = base
                q = f"?{p}={requests.utils.quote(sink, safe='')}"
                if "?" in base:
                    u = base + "&" + q[1:]
                else:
                    u = base + q
                r = session.get(u, allow_redirects=False, timeout=8, verify=False)
                loc = r.headers.get("Location","")
                if loc.startswith("//") or "evil" in loc:
                    findings.append({
                        "severity":"MEDIUM",
                        "category":"OpenRedirect",
                        "url":u, "param":p,
                        "evidence":f"Reflected into Location: {loc[:120]}"
                    })
            except Exception:
                pass

    return findings
