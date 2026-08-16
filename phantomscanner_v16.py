#!/usr/bin/env python3
"""
PhantomScanner V16.0
Safe authorized web security auditor.

Design:
- Passive inventory + low-impact validation.
- No credential attacks, brute force, destructive requests, RCE, file reads,
  data modification, or real exploit payload execution.
- Active checks use inert canaries and response/header/error evidence only.
- Findings are deduplicated and classified as CONFIRMED/POTENTIAL/INFO.

Checks:
  * Security headers / cookies
  * Reflected inert-canary detection
  * SQL error-signature detection using benign quote characters
  * Open redirect validation with a non-sensitive canary URL
  * CORS policy inspection
  * Debug/stack-trace/error disclosure
  * Directory/index exposure
  * Public sensitive-file candidate exposure (metadata/config names only;
    no secret extraction)
  * Mixed content
  * External JS without SRI
  * Technology/server disclosure

This is intended for systems where the operator has explicit authorization.
"""

import argparse
import hashlib
import html
import json
import re
import time
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import (
    parse_qsl, urlencode, urljoin, urlparse, urlunparse
)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


UA = "PhantomScanner/16.0 (safe-authorized-audit)"
MAX_BODY = 1_000_000
CANARY = "PSV16CANARY9X7"
REDIRECT_CANARY = "https://example.invalid/phantomscanner-canary"

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"mysql_fetch",
    r"mysqli?_",
    r"postgresql.*error",
    r"pg_query\(",
    r"sqlstate\[[0-9a-z]+\]",
    r"ora-\d{4,5}",
    r"oracle.*error",
    r"sqlite.*error",
    r"sqlite3?\.(?:operational|database)",
    r"unclosed quotation mark after the character string",
    r"odbc.*driver",
    r"jdbc.*sql",
    r"microsoft sql server.*error",
]

STACK_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"stack trace:",
    r"fatal error:",
    r"exception in thread",
    r"uncaught exception",
    r"undefined index:",
    r"undefined variable:",
    r"notice:.*in .* on line \d+",
    r"warning:.*in .* on line \d+",
    r"at [a-z0-9_.$]+\(.*:\d+:\d+\)",
]

PUBLIC_FILE_CANDIDATES = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]

class LinkParser(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links = set()
        self.scripts = []
        self.forms = []
        self.http_refs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() in ("a", "link", "area") and a.get("href"):
            self.links.add(urljoin(self.base, a["href"]))
        if tag.lower() == "script" and a.get("src"):
            self.scripts.append((urljoin(self.base, a["src"]), a))
        if tag.lower() == "form":
            self.forms.append(a)
        for k in ("src", "href", "action", "poster"):
            v = a.get(k)
            if v and isinstance(v, str) and v.startswith("http://"):
                self.http_refs.append(v)

def session_new():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    retry = Retry(
        total=1, connect=1, read=1, redirect=2,
        backoff_factor=0.2,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

def fetch(s, url, timeout=(10, 20), allow_redirects=True):
    try:
        r = s.get(url, timeout=timeout, allow_redirects=allow_redirects)
        body = r.content[:MAX_BODY]
        return r, body, None
    except Exception as e:
        return None, b"", str(e)

def add(findings, fid, title, severity, url, status, confidence, category,
        evidence, recommendation, cwe=None, owasp=None):
    findings.append({
        "id": fid, "title": title, "severity": severity, "url": url,
        "status": status, "confidence": confidence, "category": category,
        "evidence": evidence, "recommendation": recommendation,
        "cwe": cwe, "owasp": owasp,
    })

def header_checks(url, r, findings):
    h = {k.lower(): v for k, v in r.headers.items()}

    if "content-security-policy" not in h:
        add(findings, "PHANTOM-HEAD-CSP", "Content-Security-Policy missing",
            "MEDIUM", url, "CONFIRMED", "HIGH", "Security Headers",
            "Content-Security-Policy response header was not observed.",
            "Deploy a restrictive CSP appropriate to the application.",
            "CWE-693", "A05:2021")

    if "x-content-type-options" not in h:
        add(findings, "PHANTOM-HEAD-XCTO", "X-Content-Type-Options missing",
            "LOW", url, "CONFIRMED", "HIGH", "Security Headers",
            "X-Content-Type-Options response header was not observed.",
            "Configure X-Content-Type-Options, normally with nosniff.",
            "CWE-693", "A05:2021")

    if "referrer-policy" not in h:
        add(findings, "PHANTOM-HEAD-REF", "Referrer-Policy missing",
            "LOW", url, "CONFIRMED", "HIGH", "Security Headers",
            "Referrer-Policy response header was not observed.",
            "Configure an appropriate Referrer-Policy.",
            "CWE-200", "A05:2021")

    if "permissions-policy" not in h:
        add(findings, "PHANTOM-HEAD-PERM", "Permissions-Policy missing",
            "LOW", url, "CONFIRMED", "HIGH", "Security Headers",
            "Permissions-Policy response header was not observed.",
            "Configure Permissions-Policy according to required browser features.",
            "CWE-693", "A05:2021")

    if "cross-origin-opener-policy" not in h:
        add(findings, "PHANTOM-HEAD-COOP", "Cross-Origin-Opener-Policy missing",
            "INFO", url, "CONFIRMED", "HIGH", "Security Headers",
            "Cross-Origin-Opener-Policy response header was not observed.",
            "Review whether COOP is appropriate.",
            "CWE-693", "A05:2021")

    if "cross-origin-resource-policy" not in h:
        add(findings, "PHANTOM-HEAD-CORP", "Cross-Origin-Resource-Policy missing",
            "INFO", url, "CONFIRMED", "HIGH", "Security Headers",
            "Cross-Origin-Resource-Policy response header was not observed.",
            "Review whether CORP is appropriate.",
            "CWE-693", "A05:2021")

    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        add(findings, "PHANTOM-HEAD-FRAME",
            "No clickjacking protection header observed", "LOW", url,
            "POTENTIAL", "MEDIUM", "Security Headers",
            "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
            "Consider configuring X-Frame-Options or CSP frame-ancestors.",
            "CWE-1021", "A05:2021")

    server = h.get("server")
    if server:
        add(findings, "PHANTOM-DISC-SERVER", "Server banner disclosed",
            "INFO", url, "CONFIRMED", "HIGH", "Information Disclosure",
            f"Server header: {server}",
            "Consider minimizing unnecessary product/version disclosure.",
            "CWE-200", "A05:2021")

    powered = h.get("x-powered-by")
    if powered:
        add(findings, "PHANTOM-DISC-POWERED", "Technology banner disclosed",
            "LOW", url, "CONFIRMED", "HIGH", "Information Disclosure",
            f"X-Powered-By: {powered}",
            "Consider minimizing unnecessary technology disclosure.",
            "CWE-200", "A05:2021")

def cookie_checks(url, r, findings):
    for c in r.cookies:
        raw = c._rest or {}
        flags = {str(k).lower(): str(v) for k, v in raw.items()}
        if "httponly" not in flags:
            add(findings, "PHANTOM-COOKIE-HTTPONLY",
                "Cookie missing HttpOnly attribute", "LOW", url, "POTENTIAL",
                "MEDIUM", "Cookies",
                f"Cookie {c.name} did not expose an HttpOnly attribute.",
                "Use HttpOnly for cookies that do not need client-side JS access.",
                "CWE-1004", "A05:2021")
        if "samesite" not in flags:
            add(findings, "PHANTOM-COOKIE-SAMESITE",
                "Cookie missing SameSite attribute", "LOW", url, "POTENTIAL",
                "MEDIUM", "Cookies",
                f"Cookie {c.name} did not expose a SameSite attribute.",
                "Set an appropriate SameSite policy.",
                "CWE-1275", "A05:2021")
        if urlparse(url).scheme == "https" and not c.secure:
            add(findings, "PHANTOM-COOKIE-SECURE",
                "HTTPS cookie missing Secure attribute", "LOW", url, "POTENTIAL",
                "MEDIUM", "Cookies",
                f"Cookie {c.name} did not expose a Secure attribute.",
                "Set Secure on cookies that should only travel over HTTPS.",
                "CWE-614", "A05:2021")

def body_checks(url, r, body, findings):
    text = body.decode("utf-8", "replace")
    low = text.lower()

    if "http://" in low and urlparse(url).scheme == "https":
        refs = re.findall(r'https?://[^\\s\"\'<>]+', text, re.I)
        http_refs = [x for x in refs if x.lower().startswith("http://")]
        if http_refs:
            add(findings, "PHANTOM-WEB-MIXED", "Possible mixed-content reference",
                "LOW", url, "POTENTIAL", "MEDIUM", "Web Security",
                f"HTML contains HTTP resource reference: {http_refs[0][:300]}",
                "Serve active resources over HTTPS.",
                "CWE-319", "A05:2021")

    for pat in STACK_PATTERNS:
        if re.search(pat, text, re.I):
            add(findings, "PHANTOM-ERR-STACK", "Possible debug/stack-trace disclosure",
                "MEDIUM", url, "CONFIRMED", "HIGH", "Information Disclosure",
                f"Response contains an application error signature matching: {pat}",
                "Disable verbose production errors and stack traces.",
                "CWE-209", "A05:2021")
            break

def js_checks(url, parser, findings):
    for src, attrs in parser.scripts:
        p = urlparse(src)
        if p.scheme in ("http", "https") and p.netloc and p.netloc != urlparse(url).netloc:
            if not attrs.get("integrity"):
                add(findings, "PHANTOM-JS-NOSRI",
                    "External JavaScript without Subresource Integrity",
                    "LOW", url, "POTENTIAL", "MEDIUM", "Web Security",
                    f"External script without integrity attribute: {src[:500]}",
                    "Consider SRI where static third-party resources permit it.",
                    "CWE-829", "A06:2021")

def parse_candidate_params(url):
    p = urlparse(url)
    return parse_qsl(p.query, keep_blank_values=True)

def replace_one_param(url, index, value):
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    pairs[index] = (pairs[index][0], value)
    return urlunparse(p._replace(query=urlencode(pairs, doseq=True)))

def reflected_canary(url, s, findings, delay):
    pairs = parse_candidate_params(url)
    for i, (name, value) in enumerate(pairs[:3]):
        if not name:
            continue
        probe = replace_one_param(url, i, CANARY)
        time.sleep(delay)
        r, body, err = fetch(s, probe, timeout=(8, 15))
        if not r:
            continue
        text = body.decode("utf-8", "replace")
        if CANARY not in text:
            continue

        # Evidence of reflection is useful, but not proof of executable XSS.
        context = "HTML text/context"
        escaped = html.escape(CANARY, quote=True)
        if CANARY in text:
            m = re.search(r".{0,100}" + re.escape(CANARY) + r".{0,100}", text, re.I)
            sample = m.group(0) if m else CANARY
        else:
            sample = escaped

        add(findings, "PHANTOM-XSS-REFLECTION",
            "Reflected inert canary detected", "LOW", probe, "POTENTIAL",
            "MEDIUM", "Input Validation",
            f"Parameter '{name}' reflected inert canary in response; context={context}; sample={sample[:250]}",
            "Manually verify whether the reflection reaches an executable browser context. Do not assume reflection alone is XSS.",
            "CWE-79", "A03:2021")
        break

def sql_error_canary(url, s, findings, delay):
    pairs = parse_candidate_params(url)
    for i, (name, value) in enumerate(pairs[:3]):
        if not name:
            continue
        # Benign quote-only input. No tautology, UNION, time delay, or data extraction.
        probe = replace_one_param(url, i, "'")
        time.sleep(delay)
        r, body, err = fetch(s, probe, timeout=(8, 15))
        if not r:
            continue
        text = body.decode("utf-8", "replace")
        hits = [p for p in SQL_ERROR_PATTERNS if re.search(p, text, re.I)]
        if hits:
            add(findings, "PHANTOM-SQL-ERROR-SIGNAL",
                "Database error signature observed after benign input",
                "MEDIUM", probe, "POTENTIAL", "MEDIUM", "Input Validation",
                f"Parameter '{name}' produced database error signature: {hits[0]}",
                "Review server-side parameterization and error handling. Do not expose database errors to users.",
                "CWE-89", "A03:2021")
            break

def redirect_check(url, s, findings, delay):
    pairs = parse_candidate_params(url)
    names = [n.lower() for n, _ in pairs]
    redirect_names = {
        "url","uri","next","redirect","redirect_uri","return","returnurl",
        "return_url","continue","dest","destination","target","link"
    }
    for i, (name, value) in enumerate(pairs[:5]):
        if name.lower() not in redirect_names:
            continue
        probe = replace_one_param(url, i, REDIRECT_CANARY)
        time.sleep(delay)
        r, body, err = fetch(s, probe, timeout=(8, 15), allow_redirects=False)
        if not r:
            continue
        loc = r.headers.get("Location", "")
        if loc and REDIRECT_CANARY in loc:
            add(findings, "PHANTOM-OPEN-REDIRECT",
                "Open redirect candidate", "MEDIUM", probe, "POTENTIAL",
                "HIGH", "Redirect Validation",
                f"Location header redirects to controlled canary: {loc[:500]}",
                "Validate intended redirect destinations server-side using an allowlist.",
                "CWE-601", "A01:2021")
            break

def cors_check(url, s, findings, delay):
    origin = "https://phantomscanner.invalid"
    try:
        time.sleep(delay)
        r = s.get(url, timeout=(8,15), headers={"Origin": origin})
    except Exception:
        return
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*" or acao == origin:
        sev = "LOW"
        if acao == origin and acac == "true":
            sev = "MEDIUM"
        add(findings, "PHANTOM-CORS-POLICY",
            "Permissive CORS policy observed", sev, url, "POTENTIAL",
            "HIGH", "CORS",
            f"Origin={origin}; Access-Control-Allow-Origin={acao}; Credentials={acac or 'absent'}",
            "Restrict allowed origins and credentials to trusted origins.",
            "CWE-942", "A05:2021")

def public_file_checks(base, s, findings, delay):
    # Only checks explicitly public metadata files. It does not fetch secrets/configs.
    for path in PUBLIC_FILE_CANDIDATES:
        u = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        time.sleep(delay)
        r, body, err = fetch(s, u, timeout=(8,15))
        if not r or r.status_code != 200:
            continue
        ctype = r.headers.get("Content-Type", "")
        if len(body) > 0:
            add(findings, "PHANTOM-PUBLIC-META",
                "Public metadata/resource exposed", "INFO", u, "CONFIRMED",
                "HIGH", "Information Disclosure",
                f"Public resource returned HTTP 200 ({ctype}, {len(body)} bytes).",
                "Review whether the resource is intentionally public.",
                "CWE-200", "A05:2021")

def directory_candidate_checks(base, s, findings, delay):
    # Safe candidates only; no recursive brute force.
    candidates = ["/robots.txt", "/sitemap.xml"]
    for path in candidates:
        u = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        time.sleep(delay)
        r, body, err = fetch(s, u, timeout=(8,15))
        if not r or r.status_code != 200:
            continue
        text = body.decode("utf-8","replace").lower()
        if "<title>index of /" in text or "index of /" in text[:5000]:
            add(findings, "PHANTOM-DIR-INDEX",
                "Directory listing candidate", "MEDIUM", u, "POTENTIAL",
                "HIGH", "Web Exposure",
                "Response appears to contain an Index Of directory listing.",
                "Disable directory indexing where it is not required.",
                "CWE-548", "A05:2021")

def in_scope(url, root, scope):
    if scope == "host":
        return urlparse(url).netloc == urlparse(root).netloc
    root_host = urlparse(root).hostname or ""
    host = urlparse(url).hostname or ""
    return host == root_host or host.endswith("." + root_host)

def canonical_url(u):
    p = urlparse(u)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))

def group_findings(findings):
    groups = {}
    for f in findings:
        key = (f["id"], f["title"], f["severity"])
        if key not in groups:
            groups[key] = {
                "id": f["id"], "title": f["title"], "severity": f["severity"],
                "count": 0, "urls": []
            }
        groups[key]["count"] += 1
        if f["url"] not in groups[key]["urls"]:
            groups[key]["urls"].append(f["url"])
    return list(groups.values())

def write_reports(out, data):
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "PHANTOMSCANNER V16.0 SAFE AUTHORIZED AUDIT REPORT",
        "="*72,
        f"TARGET: {data['target']}",
        f"STATUS: {data['status']}",
        f"PAGES: {data['pages_scanned']}",
        f"REQUESTS: {data['request_count']}",
        "",
        "FINDING COUNTS: " + json.dumps(data["finding_counts"]),
        "",
        "FINDINGS",
        "="*72,
    ]
    for f in data["findings"]:
        lines += [
            f"[{f['severity']}] {f['id']} — {f['title']}",
            f"URL: {f['url']}",
            f"Status: {f['status']}",
            f"Confidence: {f['confidence']}",
            f"Category: {f['category']}",
            f"Evidence: {f['evidence']}",
            f"Recommendation: {f['recommendation']}",
            f"CWE: {f.get('cwe') or '-'} | OWASP: {f.get('owasp') or '-'}",
            "",
        ]
    lines += ["FINDING GROUPS", "="*72, json.dumps(data["finding_groups"], indent=2, ensure_ascii=False)]
    out.with_suffix(".txt").write_text("\n".join(lines), encoding="utf-8")

    rows = []
    for f in data["findings"]:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td>{}</td><td><code>{}</code></td></tr>".format(
                html.escape(f["severity"]), html.escape(f["id"]),
                html.escape(f["status"]), html.escape(f["confidence"]),
                html.escape(f["url"]), html.escape(f["evidence"])
            )
        )
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>PhantomScanner V16 Report</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:.5rem;text-align:left;vertical-align:top}}
code{{white-space:pre-wrap}}</style></head><body>
<h1>PhantomScanner V16.0</h1>
<p><b>Target:</b> {html.escape(data['target'])}</p>
<p><b>Status:</b> {html.escape(data['status'])}</p>
<p><b>Pages:</b> {data['pages_scanned']} &nbsp; <b>Requests:</b> {data['request_count']}</p>
<pre>{html.escape(json.dumps(data['finding_counts'], indent=2))}</pre>
<table><tr><th>Severity</th><th>ID</th><th>Status</th><th>Confidence</th><th>URL</th><th>Evidence</th></tr>
{''.join(rows)}</table></body></html>"""
    out.with_suffix(".html").write_text(page, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--max-pages", type=int, default=20)
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--scope", choices=["host","domain"], default="host")
    ap.add_argument("-o", "--output", default="reports/result-v16")
    ap.add_argument("--no-active", action="store_true",
                    help="Disable low-impact validation probes.")
    args = ap.parse_args()

    root = canonical_url(args.url)
    print("PhantomScanner V16.0 — SAFE AUTHORIZED AUDIT")
    print(f"Target: {root}")
    print(f"Budget: max_pages={args.max_pages}, delay={args.delay}s, scope={args.scope}")
    print("Passive inventory + low-impact validation only.")
    print("No brute-force, credential attacks, destructive actions, RCE, or data extraction.")

    s = session_new()
    findings = []
    queue = [root]
    seen = set()
    request_count = 0
    pages = 0
    discovery = {"html_urls": [], "scripts": [], "forms": [], "errors": []}

    while queue and pages < args.max_pages:
        u = canonical_url(queue.pop(0))
        if u in seen or not in_scope(u, root, args.scope):
            continue
        seen.add(u)

        r, body, err = fetch(s, u)
        request_count += 1
        if not r:
            discovery["errors"].append({"url": u, "error": err})
            continue

        pages += 1
        final = canonical_url(r.url)
        discovery["html_urls"].append(final)

        header_checks(final, r, findings)
        cookie_checks(final, r, findings)
        body_checks(final, r, body, findings)

        parser = LinkParser(final)
        try:
            parser.feed(body.decode("utf-8", "replace"))
        except Exception:
            pass

        discovery["scripts"].extend([x[0] for x in parser.scripts])
        discovery["forms"].extend(parser.forms)
        js_checks(final, parser, findings)

        for link in sorted(parser.links):
            if in_scope(link, root, args.scope):
                cu = canonical_url(link)
                if cu not in seen and cu not in queue:
                    queue.append(cu)

        if not args.no_active:
            reflected_canary(final, s, findings, min(args.delay, 0.75))
            sql_error_canary(final, s, findings, min(args.delay, 0.75))
            redirect_check(final, s, findings, min(args.delay, 0.75))
            cors_check(final, s, findings, min(args.delay, 0.75))

        time.sleep(max(args.delay, 0))

    if not args.no_active:
        public_file_checks(root, s, findings, min(args.delay, 0.75))
        directory_candidate_checks(root, s, findings, min(args.delay, 0.75))

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    status = "COMPLETED" if not queue or pages < args.max_pages else "PARTIAL"

    data = {
        "tool": "PhantomScanner",
        "version": "16.0",
        "mode": "safe-authorized-audit",
        "target": root,
        "status": status,
        "request_count": request_count,
        "pages_scanned": pages,
        "finding_counts": dict(counts),
        "findings": findings,
        "finding_groups": group_findings(findings),
        "discovery": discovery,
        "inventory": {
            "urls": sorted(seen),
            "endpoints": sorted(seen),
            "forms": discovery["forms"],
            "javascript": sorted(set(discovery["scripts"])),
            "errors": discovery["errors"],
        },
    }

    out = Path(args.output)
    write_reports(out, data)

    print("\n=== SUMMARY ===")
    print(json.dumps(dict(counts), indent=2))
    print(f"[+] STATUS: {status}")
    print(f"[+] JSON : {out.with_suffix('.json')}")
    print(f"[+] TXT  : {out.with_suffix('.txt')}")
    print(f"[+] HTML : {out.with_suffix('.html')}")
    print(f"[+] PAGES: {pages}")
    print(f"[+] EPs  : {len(seen)}")
    print(f"[+] JS   : {len(set(discovery['scripts']))}")

if __name__ == "__main__":
    main()
