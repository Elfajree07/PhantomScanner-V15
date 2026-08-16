#!/usr/bin/env python3
import argparse, json, html
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse

SEV_RANK={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
RULES={
'PHANTOM-HEAD-CSP':('Content-Security-Policy missing','MEDIUM','Header absence was directly observed in an applicable HTTP response.','CSP defense-in-depth protection is unavailable. This finding alone does not demonstrate XSS or script execution.','Deploy an appropriate Content-Security-Policy compatible with required resources.'),
'PHANTOM-COOKIE-HTTPONLY':('Cookie missing HttpOnly attribute','LOW','A Set-Cookie observation did not contain HttpOnly.','A script running in the affected origin may access a cookie that could otherwise be protected from JavaScript.','Set HttpOnly on cookies that do not intentionally require JavaScript access.'),
'PHANTOM-COOKIE-SAMESITE':('Cookie missing SameSite attribute','LOW','A Set-Cookie observation did not contain SameSite.','Cross-site cookie handling is less explicitly restricted; actual CSRF impact depends on the affected cookie and flow.','Use an appropriate SameSite value, normally Lax or Strict where compatible.'),
'PHANTOM-COOKIE-SECURE':('HTTPS cookie missing Secure attribute','LOW','A cookie observed over HTTPS did not contain Secure.','The cookie is not explicitly restricted to secure transport by the Secure flag.','Set Secure on sensitive cookies intended to travel only over HTTPS.'),
'PHANTOM-HEAD-FRAME':('No clickjacking protection header observed','LOW','Neither X-Frame-Options nor an applicable CSP frame-ancestors directive was observed.','Clickjacking defense-in-depth may be weaker; exploitability depends on framing behavior and application flow.','Use CSP frame-ancestors and/or X-Frame-Options as appropriate.'),
'PHANTOM-HEAD-PERM':('Permissions-Policy missing','LOW','Permissions-Policy response header was absent.','Browser feature access is less explicitly constrained by response policy.','Define a Permissions-Policy appropriate to features the application needs.'),
'PHANTOM-HEAD-REF':('Referrer-Policy missing','LOW','Referrer-Policy response header was absent.','Referrer information is governed by browser defaults rather than an explicit application policy.','Set an appropriate Referrer-Policy.'),
'PHANTOM-HEAD-XCTO':('X-Content-Type-Options missing','LOW','X-Content-Type-Options response header was absent.','The application does not explicitly request nosniff behavior through this header.','Set X-Content-Type-Options: nosniff for applicable responses.'),
'PHANTOM-JS-NOSRI':('External JavaScript without Subresource Integrity','LOW','An externally hosted JavaScript resource was observed without an integrity attribute.','There is less protection against unexpected modification of a third-party script resource.','Where practical, pin third-party scripts with Subresource Integrity and appropriate CSP.'),
'PHANTOM-WEB-MIXED':('Possible mixed-content reference','LOW','An HTTP resource reference was observed in an HTTPS document.','Depending on resource type and browser behavior, insecure resource loading can weaken transport security.','Use HTTPS URLs for all resources.'),
'PHANTOM-DISC-SERVER':('Server banner disclosed','INFO','A Server response header exposed server software information.','This can aid fingerprinting but is not, by itself, evidence of a vulnerability.','Minimize unnecessary server/version disclosure where practical.'),
'PHANTOM-DISC-POWERED':('Technology banner disclosed','LOW','A technology-identifying response header was observed.','Technology disclosure can aid fingerprinting but does not by itself demonstrate compromise.','Remove unnecessary technology-identifying headers where practical.'),
'PHANTOM-HEAD-COOP':('Cross-Origin-Opener-Policy missing','INFO','Cross-Origin-Opener-Policy response header was absent.','The application does not explicitly establish COOP isolation through this response header.','Evaluate whether an appropriate COOP policy is needed.'),
'PHANTOM-HEAD-CORP':('Cross-Origin-Resource-Policy missing','INFO','Cross-Origin-Resource-Policy response header was absent.','The application does not explicitly establish CORP restrictions through this response header.','Evaluate whether an appropriate CORP policy is needed.'),
'PHANTOM-PUBLIC-META':('Public metadata/resource exposed','INFO','The referenced public resource returned a successful response.','Public availability alone is not evidence of a vulnerability; content must be reviewed for sensitive information.','Review the resource contents and ensure sensitive information is not exposed.')}

def norm(data):
    out=[]
    for f in data.get('findings',[]):
        fid=str(f.get('id') or 'UNKNOWN'); r=RULES.get(fid)
        out.append({'id':fid,'title':f.get('title') or (r[0] if r else fid),'severity':str(f.get('severity') or (r[1] if r else 'INFO')).upper(),'url':f.get('url') or '','evidence':f.get('evidence') or '','status':str(f.get('status') or '').upper(),'confidence':str(f.get('confidence') or '').upper()})
    return out

def triage(fs):
    gs=OrderedDict()
    for f in fs:
        k=(f['id'],f['title']); g=gs.setdefault(k,{'id':f['id'],'title':f['title'],'severity':f['severity'],'statuses':set(),'conf':set(),'urls':[],'ev':[]})
        if f['status']: g['statuses'].add(f['status'])
        if f['confidence']: g['conf'].add(f['confidence'])
        if f['url'] and f['url'] not in g['urls']: g['urls'].append(f['url'])
        if f['evidence'] and f['evidence'] not in g['ev']: g['ev'].append(f['evidence'])
    result=[]
    for g in sorted(gs.values(),key=lambda x:(SEV_RANK.get(x['severity'],9),x['id'])):
        r=RULES.get(g['id'],('Technical condition observed','INFO','','Impact requires manual validation.','Review as appropriate.'))
        status='CONFIRMED' if 'CONFIRMED' in g['statuses'] and ('HIGH' in g['conf'] or not g['conf']) else ('VALIDATED' if g['statuses'] & {'VALIDATED','CONFIRMED'} else 'OBSERVED')
        if g['id']=='PHANTOM-PUBLIC-META': status='OBSERVED'
        result.append({'id':g['id'],'title':g['title'],'severity':g['severity'],'status':status,'confidence':'HIGH' if 'HIGH' in g['conf'] else ('MEDIUM' if g['conf'] else 'UNSPECIFIED'),'hosts':sorted({urlparse(u).netloc for u in g['urls'] if u}),'affected_urls':g['urls'],'evidence':g['ev'],'validation':r[2],'impact':r[3],'recommendation':r[4],'exploitability_proven':False})
    return result

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('-i','--input',required=True); ap.add_argument('-o','--output'); a=ap.parse_args()
    src=Path(a.input); base=Path(a.output) if a.output else src.with_name(src.stem+'-triage'); d=json.loads(src.read_text(encoding='utf-8')); fs=norm(d); groups=triage(fs)
    out={'tool':'PhantomScanner V16.1 Proof-Aware Triage','source':str(src),'source_status':d.get('status'),'pages_scanned':d.get('pages_scanned'),'request_count':d.get('request_count'),'raw_findings':len(fs),'unique_classes':len(groups),'exploitability_proven':False,'findings':groups}
    base.parent.mkdir(parents=True,exist_ok=True)
    (Path(str(base)+'.json')).write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
    txt=["="*72,'PHANTOMSCANNER V16.1 — PROOF-AWARE TRIAGE',"="*72,f"Raw findings: {len(fs)}",f"Unique classes: {len(groups)}",f"Source status: {d.get('status')}",'Exploitability proven: NO','']
    for g in groups:
        txt += ['-'*72,f"[{g['severity']}] {g['id']}",f"Title: {g['title']}",f"Status: {g['status']}",f"Confidence: {g['confidence']}",f"Hosts: {', '.join(g['hosts'])}",'URLs:']+['  - '+u for u in g['affected_urls'][:25]]+['Evidence:']+['  - '+e for e in g['evidence'][:5]]+[f"Validation: {g['validation']}",f"Impact: {g['impact']}",f"Recommendation: {g['recommendation']}",'']
    Path(str(base)+'.txt').write_text('\n'.join(txt),encoding='utf-8')
    md=['# PhantomScanner V16.1 — Bug Bounty Triage','', '> **CONFIRMED validates the technical condition only; it does not prove exploitability or compromise.**','',f"- Source status: `{d.get('status')}`",f"- Raw findings: `{len(fs)}`",f"- Unique classes: `{len(groups)}`",'']
    for i,g in enumerate(groups,1):
        md += [f"## {i}. {g['title']}",'',f"- **ID:** `{g['id']}`",f"- **Severity:** `{g['severity']}`",f"- **Status:** `{g['status']}`",f"- **Confidence:** `{g['confidence']}`",'- **Exploitability proven:** `No`','', '### Affected hosts','']+['- `'+h+'`' for h in g['hosts']]+['','### Affected URLs','']+['- `'+u+'`' for u in g['affected_urls'][:25]]+['','### Evidence','']+['- `'+e+'`' for e in g['evidence'][:5]]+['','### Validation','',g['validation'],'','### Impact','',g['impact'],'','### Recommendation','',g['recommendation'],'']
    Path(str(base)+'.md').write_text('\n'.join(md),encoding='utf-8')
    cards=[]
    for g in groups:
        cards.append('<section><h2>['+html.escape(g['severity'])+'] '+html.escape(g['title'])+'</h2><p><b>ID:</b> '+html.escape(g['id'])+' &nbsp; <b>Status:</b> '+g['status']+' &nbsp; <b>Confidence:</b> '+g['confidence']+'</p><p><b>Exploitability proven:</b> No</p><h3>Affected URLs</h3><ul>'+''.join('<li><code>'+html.escape(u)+'</code></li>' for u in g['affected_urls'][:25])+'</ul><h3>Evidence</h3><ul>'+''.join('<li><code>'+html.escape(e)+'</code></li>' for e in g['evidence'][:5])+'</ul><h3>Validation</h3><p>'+html.escape(g['validation'])+'</p><h3>Impact</h3><p>'+html.escape(g['impact'])+'</p><h3>Recommendation</h3><p>'+html.escape(g['recommendation'])+'</p></section>')
    doc='<!doctype html><meta charset="utf-8"><title>PhantomScanner V16.1 Triage</title><style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}section{border:1px solid #ccc;border-radius:10px;padding:1rem;margin:1rem 0}code{word-break:break-all}.note{padding:1rem;border-left:4px solid #555;background:#f5f5f5}</style><h1>PhantomScanner V16.1 — Proof-Aware Triage</h1><div class="note"><b>Important:</b> CONFIRMED validates the technical condition only; it does not prove exploitability.</div>'+''.join(cards)
    Path(str(base)+'.html').write_text(doc,encoding='utf-8')
    print('OK'); print('JSON:',str(base)+'.json'); print('TXT :',str(base)+'.txt'); print('MD  :',str(base)+'.md'); print('HTML:',str(base)+'.html'); print('Raw findings:',len(fs)); print('Unique classes:',len(groups))
if __name__=='__main__': main()
