#!/usr/bin/env python3
"""NEUTRA — ARCHIVE: ONLINE · SECTOR 7G
Single-file OSINT + threat-intel + people-search dashboard. 3.8+, stdlib only.

Env: PORT, NEUTRA_HOST, NEUTRA_AUTH="user:pass",
     NUMVERIFY_KEY, GITHUB_TOKEN, SHODAN_KEY, GREYNOISE_KEY, VT_KEY, OTX_KEY,
     IPQS_KEY, VERIPHONE_KEY, COURTLISTENER_KEY, HUNTER_KEY, PIPL_KEY,
     EMAILREP_KEY, OPENCORPORATES_KEY, FEC_API_KEY, HIBP_KEY
"""

import base64, hashlib, http.server, ipaddress, json, os, re, socket, sys, threading, time, uuid, webbrowser
import urllib.error as ue, urllib.parse as up, urllib.request as ur
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("NEUTRA_DATA", os.path.join(HERE, "neutra_data"))
os.makedirs(DATA, exist_ok=True)
HOST = os.environ.get("NEUTRA_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT") or os.environ.get("NEUTRA_PORT") or 8765)
AUTH = os.environ.get("NEUTRA_AUTH")
UA = "NeutraArchive/5.0 (+sector-7g; public-data research)"
TY = {"A":1,"AAAA":28,"CNAME":5,"MX":15,"NS":2,"SOA":6,"TXT":16,"PTR":12}
DBL = threading.Lock()

# ── archive banner ───────────────────────────────────────────────────────
BANNER = r"""
  ███╗   ██╗███████╗██╗   ██╗████████╗██████╗  █████╗
  ████╗  ██║██╔════╝██║   ██║╚══██╔══╝██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗  ██║   ██║   ██║   ██████╔╝███████║
  ██║╚██╗██║██╔══╝  ██║   ██║   ██║   ██╔══██╗██╔══██║
  ██║ ╚████║███████╗╚██████╔╝   ██║   ██║  ██║██║  ██║
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
      A R C H I V E   ·   O N L I N E   ·   S E C T O R   7 G
"""

class RateLimiter:
    def __init__(self): self.calls={}; self.lock=threading.Lock()
    def check(self, key, limit, window=60):
        now=time.time()
        with self.lock:
            self.calls.setdefault(key,[])
            self.calls[key]=[t for t in self.calls[key] if now-t<window]
            if len(self.calls[key])>=limit: raise ValueError("rate limit %s"%key)
            self.calls[key].append(now)
RL = RateLimiter()

def _req(url,h=None,t=15,method=None,data=None):
    return ur.Request(url, headers={"User-Agent":UA, **(h or {})}, method=method, data=data)
def get(url,h=None,t=15):
    with ur.urlopen(_req(url,h,t), timeout=t) as r: return json.loads(r.read(3_000_000))
def get_text(url,h=None,t=15):
    with ur.urlopen(_req(url,h,t), timeout=t) as r: return r.read(3_000_000).decode("utf-8","replace")
def post_json(url,payload,h=None,t=20):
    with ur.urlopen(_req(url,{"Content-Type":"application/json",**(h or {})},t,method="POST",
                            data=json.dumps(payload).encode()),timeout=t) as r:
        return json.loads(r.read(3_000_000))
def post_form(url,fields,h=None,t=20):
    with ur.urlopen(_req(url,{"Content-Type":"application/x-www-form-urlencoded",**(h or {})},t,
                            method="POST",data=up.urlencode(fields).encode()),timeout=t) as r:
        return json.loads(r.read(3_000_000))
def head_ok(url,t=7):
    for m in ("HEAD","GET"):
        try:
            with ur.urlopen(_req(url,t=t,method=m), timeout=t) as r:
                if r.status==200: return True
        except Exception: continue
    return False
def doh(name,typ):
    j = get("https://cloudflare-dns.com/dns-query?name=%s&type=%s"%(up.quote(name),typ),
            {"accept":"application/dns-json"})
    return [a["data"].strip('"') for a in j.get("Answer",[]) if a.get("type")==TY[typ]]
def host_of(q):
    q=q.strip()
    if "@" in q and "://" not in q: return q.split("@")[-1].lower()
    return (up.urlparse(q if "://" in q else "//"+q).hostname or "").lower()
def reg_domain(h):
    if not h: return ""
    p=h.split("."); return ".".join(p[-2:]) if len(p)>=2 else h
def public_only(h):
    for i in socket.getaddrinfo(h,None):
        if not ipaddress.ip_address(i[4][0]).is_global:
            raise ValueError("blocked: %s is private"%h)

def detect(q):
    q=q.strip()
    if not q or len(q)>300: return "unknown"
    try: ipaddress.ip_address(q); return "ip"
    except ValueError: pass
    for n,rx in [("url",r"https?://\S+"),("email",r"[\w.+-]+@[\w-]+(\.[\w-]+)+"),
                 ("cve",r"(?i)CVE-\d{4}-\d{4,}"),("asn",r"(?i)AS\d{1,10}"),
                 ("wallet",r"(?i)(0x[a-f0-9]{40}|bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})"),
                 ("hash",r"(?i)([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})"),
                 ("coords",r"-?\d{1,2}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?"),
                 ("phone",r"\+?\d[\d\s\-()]{6,20}\d"),
                 ("domain",r"(?i)([a-z0-9-]{1,63}\.)+[a-z]{2,}"),
                 ("name",r"[A-Za-z][A-Za-z'\-]+\s+[A-Za-z][A-Za-z'\-]+"),
                 ("username",r"@[a-zA-Z0-9_.]{2,30}"),
                 ("username",r"[a-zA-Z0-9_]{2,30}")]:
        if re.fullmatch(rx,q): return n
    return "unknown"

MODS, FOR = {}, {}
CATS = ["Domain","Network","Email","Username","Phone","People","Threat","Search","Geo","Crypto","Archive"]
def register(mid,label,why,cat,applies,fn,weight=1.0,region="global",ai=True):
    MODS[mid]={"id":mid,"label":label,"why":why,"category":cat,"applies":applies,
               "fn":fn,"weight":weight,"region":region,"ai":ai}
    for t in applies: FOR.setdefault(t,[]).append(mid)

# ═══════════════════════════════════════════════════════════════════════
#  IP / NETWORK
# ═══════════════════════════════════════════════════════════════════════
def ipinfo(ip):
    try:
        RL.check("ip-api",40)
        j = get("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query,timezone"%ip)
        if j.get("status")!="fail":
            place=", ".join(x for x in [j.get("city"),j.get("regionName"),j.get("country")] if x)
            return {"rows":[("IP",j.get("query",ip)),("Place",place),
                            ("Coordinates","%s, %s"%(j.get("lat"),j.get("lon"))),
                            ("Timezone",j.get("timezone","?")),
                            ("Network",j.get("isp") or j.get("org") or "?"),
                            ("ASN",j.get("as","?"))],
                    "geo":(j.get("lat"),j.get("lon"),"%s (%s)"%(ip,j.get("city","?")))}
    except Exception: pass
    j = get("https://ipwho.is/"+ip)
    if not j.get("success"): raise ValueError(j.get("message","lookup failed"))
    return {"rows":[("IP",j.get("ip",ip)),
                    ("Place",", ".join(x for x in [j.get("city"),j.get("region"),j.get("country")] if x)),
                    ("Coordinates","%s, %s"%(j.get("latitude"),j.get("longitude"))),
                    ("Timezone",(j.get("timezone") or {}).get("id","?")),
                    ("Network",(j.get("connection") or {}).get("isp","?")),
                    ("ASN",(j.get("connection") or {}).get("asn","?"))],
            "geo":(j.get("latitude"),j.get("longitude"),"%s (%s)"%(ip,j.get("city","?")))}

def p_ipgeo(q): return ipinfo(q)
def p_iprdap(q):
    j=get("https://rdap.org/ip/"+q)
    return {"rows":[("Owner block",j.get("name","?")),("Country",j.get("country","?")),
                    ("Range","%s - %s"%(j.get("startAddress"),j.get("endAddress"))),
                    ("Type",j.get("type","?"))]}
def p_asn(q):
    j=get("https://stat.ripe.net/data/as-overview/data.json?resource="+q.upper())["data"]
    return {"rows":[("Holder",j.get("holder","?")),
                    ("Announced","yes" if j.get("announced") else "no")]}
def p_ip_abuse(q):
    try:
        RL.check("ip-api",40)
        j=get("http://ip-api.com/json/%s?fields=status,proxy,hosting,mobile,query"%q)
        if j.get("status")=="fail": raise ValueError("lookup failed")
        proxy,hosting,mobile=j.get("proxy"),j.get("hosting"),j.get("mobile")
    except Exception:
        j=get("https://ipwho.is/"+q)
        proxy=(j.get("security") or {}).get("proxy") or (j.get("security") or {}).get("vpn")
        hosting=(j.get("connection") or {}).get("type")=="hosting"
        mobile=(j.get("connection") or {}).get("type")=="mobile"
    return {"rows":[("IP",q),("Proxy/VPN","YES" if proxy else "no"),
                    ("Hosting","YES" if hosting else "no"),("Mobile","YES" if mobile else "no")],
            "status":"warn" if proxy or hosting else "ok"}
def p_reverse_dns(q):
    try:
        h=socket.gethostbyaddr(q); return {"rows":[("PTR",h[0]),("Aliases",", ".join(h[1]) or "-")]}
    except Exception as e: return {"rows":[("PTR","none"),("Error",str(e))],"status":"warn"}
def p_shodan_idb(q):
    """Shodan InternetDB — free, no key."""
    try:
        j=get("https://internetdb.shodan.io/"+q,t=12)
        ports=j.get("ports",[]) or []
        return {"rows":[("Open ports",", ".join(map(str,ports)) or "none"),
                        ("Hostnames",", ".join(j.get("hostnames",[])) or "none"),
                        ("CPEs",", ".join(j.get("cpes",[])[:8]) or "none"),
                        ("Tags",", ".join(j.get("tags",[])) or "none"),
                        ("Vulns",", ".join(j.get("vulns",[])[:15]) or "none")],
                "status":"warn" if ports else "ok"}
    except ue.HTTPError as e:
        if e.code==404: return {"rows":[("Result","no record")],"status":"ok"}
        raise
def p_greynoise(q):
    """GreyNoise Community API — free tier, no key required for basic."""
    try:
        j=get("https://api.greynoise.io/v3/community/"+q,t=12)
        return {"rows":[("Noise","yes" if j.get("noise") else "no"),
                        ("Riot","yes" if j.get("riot") else "no"),
                        ("Classification",j.get("classification","unknown")),
                        ("Name",j.get("name","?")),
                        ("Last seen",j.get("last_seen","?"))],
                "status":"bad" if j.get("noise") and not j.get("riot") else "ok"}
    except ue.HTTPError as e:
        if e.code==404: return {"rows":[("Result","not observed by GreyNoise")],"status":"ok"}
        raise

# ═══════════════════════════════════════════════════════════════════════
#  DOMAIN
# ═══════════════════════════════════════════════════════════════════════
def p_dns(q):
    d=host_of(q)
    return {"rows":[(t,", ".join(doh(d,t)) or "none") for t in TY]}
def p_certs(q):
    d=reg_domain(host_of(q))
    j=get("https://crt.sh/?q=%25."+up.quote(d)+"&output=json",t=30)
    names=sorted({x.lstrip("*.") for r in j for x in r["name_value"].split("\n") if x.endswith(d)})
    return {"rows":[("Hostnames",len(names))]+[("",n) for n in names[:60]]}
def p_crt_history(q):
    d=reg_domain(host_of(q))
    j=get("https://crt.sh/?q=%25."+up.quote(d)+"&output=json",t=30)
    seen={}
    for r in j:
        k=r.get("issuer_name","?")
        seen[k]=seen.get(k,0)+1
    return {"rows":[("Total certs",len(j))]+[(k,v) for k,v in list(seen.items())[:10]]}
def p_subdomains(q):
    d=reg_domain(host_of(q))
    try:
        t=get_text("https://api.hackertarget.com/hostsearch/?q="+up.quote(d),t=20)
        subs=sorted({l.split(",")[0] for l in t.splitlines() if "," in l})
        return {"rows":[("Found",len(subs))]+[("",s) for s in subs[:60]]}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_rdap(q):
    j=get("https://rdap.org/domain/"+reg_domain(host_of(q)))
    ev={e["eventAction"]:e["eventDate"][:10] for e in j.get("events",[])}
    reg="hidden"
    for e in j.get("entities",[]):
        if "registrar" in e.get("roles",[]):
            for v in e.get("vcardArray",[0,[]])[1]:
                if v[0]=="fn": reg=v[3]
    return {"rows":[("Registrar",reg),("Registered",ev.get("registration","?")),
                    ("Expires",ev.get("expiration","?")),("Updated",ev.get("last changed","?")),
                    ("Name servers",", ".join(n["ldhName"] for n in j.get("nameservers",[])) or "?"),
                    ("Status",", ".join(j.get("status",[])) or "?")]}
def p_hosting(q):
    d=host_of(q); ip=socket.gethostbyname(d)
    r=ipinfo(ip); r["rows"].insert(0,("Site",d)); return r
def p_wayback(q):
    d=host_of(q)
    j=get("https://archive.org/wayback/available?url="+up.quote(d))
    c=j.get("archived_snapshots",{}).get("closest")
    return {"rows":[("Closest snapshot",c["timestamp"][:8] if c else "none"),
                    ("Link",c["url"] if c else "-")]}
def p_wayback_cdx(q):
    d=host_of(q)
    try:
        t=get_text("https://web.archive.org/cdx/search/cdx?url=%s&output=json&limit=50&collapse=timestamp:6&fl=timestamp,original,statuscode,mimetype"%up.quote(d),t=25)
        rows=json.loads(t)
        if not rows: return {"rows":[("Result","no captures")]}
        header,rows=rows[0],rows[1:]
        out=[("Captures",len(rows))]
        for r in rows[:30]:
            out.append((r[0][:8],r[2]+" · "+r[3]+" · "+r[1]))
        return {"rows":out}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_archive_today(q):
    d=host_of(q)
    try:
        with ur.urlopen(_req("https://archive.ph/newest/https://"+d,t=12),timeout=12) as r:
            return {"rows":[("Archive.today","captured"),("URL",r.geturl())],"status":"ok"}
    except Exception as e:
        return {"rows":[("Archive.today","no recent snapshot"),("Detail",str(e)[:120])],"status":"warn"}
def p_emailsec(q):
    d=reg_domain(host_of(q))
    spf=[t for t in doh(d,"TXT") if t.startswith("v=spf1")]
    dm=[t for t in doh("_dmarc."+d,"TXT") if t.startswith("v=DMARC1")]
    pol=(re.search(r"p=(\w+)",dm[0]) or [0,"?"])[1] if dm else "missing"
    bad=not spf or pol in ("missing","none")
    return {"rows":[("SPF","present" if spf else "MISSING"),("DMARC policy",pol),
                    ("Overall","spoofable" if bad else "hardened")],
            "status":"warn" if bad else "ok"}
def p_headers(q):
    d=host_of(q); public_only(d)
    try: h=ur.urlopen(_req("https://"+d,t=12),timeout=12).headers
    except ue.HTTPError as e: h=e.headers
    want=["strict-transport-security","content-security-policy","x-frame-options",
          "x-content-type-options","referrer-policy","permissions-policy"]
    miss=[w for w in want if not h.get(w)]
    return {"rows":[(w,"present" if w not in miss else "MISSING") for w in want]
                    +[("Server",h.get("server","hidden")),("Missing",str(len(miss)))],
            "status":"ok" if len(miss)<3 else "warn"}
def p_robots(q):
    d=host_of(q); out=[]
    for path in ("/robots.txt","/.well-known/security.txt","/sitemap.xml"):
        try:
            t=get_text("https://"+d+path,t=10); out.append((path,"found (%d bytes)"%len(t)))
        except Exception: out.append((path,"not found"))
    return {"rows":out}
def p_tech(q):
    d=host_of(q); public_only(d)
    try:
        r=ur.urlopen(_req("https://"+d,t=12),timeout=12)
        body=r.read(400_000).decode("utf-8","replace"); h=r.headers
    except ue.HTTPError as e:
        body=e.read(400_000).decode("utf-8","replace"); h=e.headers
    sigs=[("WordPress","wp-content"),("Drupal","sites/default"),("Joomla","com_content"),
          ("React","data-reactroot"),("Vue","data-v-"),("Next.js","__NEXT_DATA__"),
          ("Shopify","cdn.shopify.com"),("Google Analytics","gtag("),("jQuery","jquery"),
          ("Bootstrap","bootstrap.min.css"),("Tailwind","tailwind")]
    tech=[n for n,s in sigs if s.lower() in body.lower()]
    return {"rows":[("Server",h.get("server","hidden")),
                    ("Powered by",h.get("x-powered-by","hidden")),
                    ("Detected tech",", ".join(tech) or "none")]}
def p_mx_provider(q):
    d=reg_domain(host_of(q))
    try: mx=doh(d,"MX")
    except Exception: mx=[]
    j=" ".join(mx).lower(); prov="unknown"
    for k,v in [("google","Google Workspace"),("outlook","Microsoft 365"),("zoho","Zoho"),
                ("yandex","Yandex"),("proton","Proton"),("mimecast","Mimecast"),
                ("proofpoint","Proofpoint"),("mail.ru","Mail.ru"),("qq.com","Tencent"),
                ("163.com","NetEase")]:
        if k in j: prov=v; break
    return {"rows":[("MX records",", ".join(mx) or "none"),("Provider",prov)]}

# ═══════════════════════════════════════════════════════════════════════
#  EMAIL
# ═══════════════════════════════════════════════════════════════════════
def p_email_breach(q):
    RL.check("xon",20)
    j=get("https://api.xposedornot.com/v1/check-email/"+up.quote(q.strip()))
    breaches=j.get("breaches",[])
    if not breaches: return {"rows":[("Result","not found in any known breach")],"status":"ok"}
    return {"rows":[("Breaches",len(breaches))]+[(b,"leaked") for b in breaches[:20]],"status":"bad"}
def p_people_email(q):
    email=q.strip().lower(); local=email.split("@")[0]
    rows=[("Email",email)]; found=0
    try:
        j=get("https://api.github.com/search/users?q="+up.quote(local))
        if j.get("total_count",0)>0: rows.append(("GitHub",j["items"][0]["html_url"])); found+=1
    except Exception: pass
    try:
        j=get("https://www.reddit.com/user/%s/about.json"%up.quote(local))
        if j.get("data",{}).get("name"): rows.append(("Reddit","reddit.com/user/"+j["data"]["name"])); found+=1
    except Exception: pass
    gh=hashlib.md5(email.encode()).hexdigest()
    try:
        j=get("https://gravatar.com/%s.json"%gh)
        if j.get("entry"): rows.append(("Gravatar",j["entry"][0].get("profileUrl","?"))); found+=1
    except Exception: pass
    rows.append(("Services found",str(found)))
    return {"rows":rows,"status":"warn" if found else "ok"}
def p_gravatar(q):
    gh=hashlib.md5(q.strip().lower().encode()).hexdigest()
    try:
        j=get("https://gravatar.com/%s.json"%gh)
        if not j.get("entry"): return {"rows":[("Result","no Gravatar profile")],"status":"ok"}
        e=j["entry"][0]
        return {"rows":[("Name",e.get("name",{}).get("formatted","?")),
                        ("About",(e.get("aboutMe","") or "")[:200]),
                        ("Profile",e.get("profileUrl","?")),
                        ("Accounts",", ".join(a.get("shortname","?") for a in e.get("accounts",[])))],
                "status":"warn"}
    except ue.HTTPError as e:
        if e.code==404: return {"rows":[("Result","no Gravatar profile")],"status":"ok"}
        raise
def p_email_disposable(q):
    d=reg_domain(host_of(q))
    try:
        t=get_text("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",t=15)
        inlist=d in t.split("\n")
    except Exception: inlist=None
    return {"rows":[("Domain",d),
                    ("Disposable","listed" if inlist else ("not listed" if inlist is False else "unknown"))],
            "status":"warn" if inlist else "ok"}
def p_email_mx(q):
    d=reg_domain(host_of(q))
    try: mx=doh(d,"MX")
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
    return {"rows":[("MX hosts",", ".join(mx) or "none"),
                    ("Deliverable","yes" if mx else "no")]}

# ── NEW: Email intelligence ──
def p_emailrep(q):
    """EmailRep.io — reputation, linked profiles, breach appearance. No key required for basic."""
    try:
        h={"Accept":"application/json"}
        key=os.environ.get("EMAILREP_KEY")
        if key: h["Key"]=key
        j=get("https://emailrep.io/"+up.quote(q.strip()),h,t=12)
        if not j.get("email"): raise ValueError("no data")
        prof=j.get("details",{}).get("profiles",[]) or []
        return {"rows":[("Email",j.get("email","?")),
                        ("Reputation",j.get("reputation","?")),
                        ("Suspicious","YES" if j.get("suspicious") else "no"),
                        ("References",str(j.get("references",0))),
                        ("Blacklisted","YES" if j.get("details",{}).get("blacklisted") else "no"),
                        ("Malicious activity","YES" if j.get("details",{}).get("malicious_activity") else "no"),
                        ("Credentials leaked","YES" if j.get("details",{}).get("credentials_leaked") else "no"),
                        ("Data breach","YES" if j.get("details",{}).get("data_breach") else "no"),
                        ("First seen",j.get("details",{}).get("first_seen","?")),
                        ("Last seen",j.get("details",{}).get("last_seen","?")),
                        ("Domain exists","yes" if j.get("details",{}).get("domain_exists") else "no"),
                        ("Profiles",", ".join(prof) if prof else "none")],
                "status":"bad" if j.get("suspicious") or j.get("details",{}).get("malicious_activity") else "warn" if prof else "ok"}
    except ue.HTTPError as e:
        if e.code==404: return {"rows":[("Result","no EmailRep data")],"status":"ok"}
        return {"rows":[("Error","HTTP %s"%e.code)],"status":"warn"}
def p_hunter_io(q):
    """Hunter.io — find professional email addresses for a domain."""
    key=os.environ.get("HUNTER_KEY")
    if not key: return {"rows":[("Needs setup","Set HUNTER_KEY to unlock Hunter.io")],"status":"warn"}
    d=host_of(q) or q
    try:
        j=get("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s&limit=10"%(up.quote(d),key),t=15)
        data=j.get("data",{}); emails=data.get("emails",[]) or []
        rows=[("Domain",data.get("domain","?")),
              ("Organization",data.get("organization","?")),
              ("Pattern",data.get("pattern","?")),
              ("Emails found",len(emails))]
        for e in emails[:10]:
            rows.append((e.get("value","?"), "%s %s"%(e.get("first_name",""),e.get("last_name",""))))
        return {"rows":rows,"status":"ok" if emails else "warn"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_ipqs_email(q):
    """IPQualityScore email validation — free tier 5,000/mo."""
    key=os.environ.get("IPQS_KEY")
    if not key: return {"rows":[("Needs setup","Set IPQS_KEY to unlock IPQS email check")],"status":"warn"}
    try:
        j=get("https://ipqualityscore.com/api/json/email/%s/%s"%(key,up.quote(q.strip())),t=12)
        return {"rows":[("Valid","yes" if j.get("valid") else "no"),
                        ("Deliverability",j.get("deliverability","?")),
                        ("Disposable","YES" if j.get("disposable") else "no"),
                        ("Fraud score",str(j.get("fraud_score","?"))),
                        ("Recent abuse","YES" if j.get("recent_abuse") else "no"),
                        ("First name",j.get("first_name","?")),
                        ("Last name",j.get("last_name","?")),
                        ("Domain",j.get("domain","?")),
                        ("Suspicious","YES" if j.get("suspicious") else "no")],
                "status":"bad" if j.get("disposable") or j.get("recent_abuse") else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_breach_directory(q):
    """BreachDirectory — search public breaches by email/username. Free tier."""
    try:
        j=get("https://breachdirectory.org/api/v1/check?email=%s"%up.quote(q.strip()),t=15)
        if not j.get("found"): return {"rows":[("Result","not found")],"status":"ok"}
        return {"rows":[("Found","yes"),
                        ("Sources",", ".join(j.get("sources",[]) or []))],
                "status":"bad"}
    except Exception as e:
        return {"rows":[("Result","BreachDirectory requires browser session"),
                        ("Detail","Manual check at breachdirectory.org")],"status":"warn"}
def p_hudson_rock_email(q):
    """Hudson Rock Cavalier — infostealer infection lookup. Free, no key required."""
    try:
        j=get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email="+up.quote(q.strip()),t=15)
        if not j.get("message") and not j.get("data"): return {"rows":[("Result","no infection data")],"status":"ok"}
        stealer=j.get("stealer","") or ""
        if stealer:
            return {"rows":[("Infected","YES"),
                            ("Stealer family",stealer),
                            ("Date compromised",j.get("date_compromised","?")),
                            ("Computer name",j.get("computer_name","?")),
                            ("Operating system",j.get("operating_system","?")),
                            ("IP address",j.get("ip","?")),
                            ("Malware path",j.get("malware_path","?")),
                            ("Anti-virus",j.get("antiviruses","?"))],
                    "status":"bad"}
        return {"rows":[("Infected","no")],"status":"ok"}
    except ue.HTTPError as e:
        if e.code==404: return {"rows":[("Result","no infostealer infections found")],"status":"ok"}
        return {"rows":[("Error","HTTP %s"%e.code)],"status":"warn"}

# ═══════════════════════════════════════════════════════════════════════
#  USERNAME
# ═══════════════════════════════════════════════════════════════════════
GLOBAL_SITES=[("Instagram","https://www.instagram.com/{}/"),("TikTok","https://www.tiktok.com/@{}"),
    ("Twitter/X","https://x.com/{}"),("LinkedIn","https://www.linkedin.com/in/{}"),
    ("Facebook","https://www.facebook.com/{}"),("Snapchat","https://www.snapchat.com/add/{}"),
    ("Telegram","https://t.me/{}"),("Reddit","https://www.reddit.com/user/{}"),
    ("YouTube","https://www.youtube.com/@{}"),("GitHub","https://github.com/{}"),
    ("Steam","https://steamcommunity.com/id/{}"),("Pinterest","https://www.pinterest.com/{}"),
    ("Twitch","https://www.twitch.tv/{}"),("Medium","https://medium.com/@{}"),
    ("DeviantArt","https://www.deviantart.com/{}"),("Flickr","https://www.flickr.com/people/{}"),
    ("Tumblr","https://{}.tumblr.com/"),("SoundCloud","https://soundcloud.com/{}"),
    ("Mastodon","https://mastodon.social/@{}"),("Bluesky","https://bsky.app/profile/{}.bsky.social"),
    ("Threads","https://www.threads.net/@{}"),("Roblox","https://www.roblox.com/user.aspx?username={}"),
    ("Xbox","https://xboxgamertag.com/search/{}"),("PSN","https://psnprofiles.com/{}"),
    ("Keybase","https://keybase.io/{}"),("About.me","https://about.me/{}"),
    ("Behance","https://www.behance.net/{}"),("Dribbble","https://dribbble.com/{}"),
    ("Kaggle","https://www.kaggle.com/{}"),("Vimeo","https://vimeo.com/{}"),
    ("Spotify","https://open.spotify.com/user/{}"),("Patreon","https://www.patreon.com/{}"),
    ("Ko-fi","https://ko-fi.com/{}"),("Buy Me a Coffee","https://www.buymeacoffee.com/{}"),
    ("Linktree","https://linktr.ee/{}"),("Mastodon (tech)","https://techhub.social/@{}"),
    ("Lemmy","https://lemmy.world/u/{}"),("Kbin","https://kbin.social/u/{}"),
    ("Hacker News","https://news.ycombinator.com/user?id={}")]
REGIONAL_SITES=[("VK","https://vk.com/{}"),("Odnoklassniki","https://ok.ru/{}"),
    ("Weibo","https://weibo.com/n/{}"),("Bilibili","https://space.bilibili.com/{}"),
    ("Zhihu","https://www.zhihu.com/people/{}"),("Douban","https://www.douban.com/people/{}/"),
    ("Ameba","https://ameblo.jp/{}/"),("NicoNico","https://www.nicovideo.jp/user/{}"),
    ("Naver Blog","https://blog.naver.com/{}"),("ShareChat","https://sharechat.com/profile/{}"),
    ("Xing","https://www.xing.com/profile/{}"),("Renren","https://www.renren.com/{}"),
    ("Kakao Story","https://story.kakao.com/{}"),("Line","https://line.me/ti/p/~{}"),
    ("WeChat","https://weixin.qq.com/{}"),("QQ","https://user.qzone.qq.com/{}")]
DEV_SITES=[("GitLab","https://gitlab.com/{}"),("Bitbucket","https://bitbucket.org/{}/"),
    ("HackerNews","https://news.ycombinator.com/user?id={}"),("Dev.to","https://dev.to/{}"),
    ("NPM","https://www.npmjs.com/~{}"),("PyPI","https://pypi.org/user/{}/"),
    ("Docker Hub","https://hub.docker.com/u/{}"),("CodePen","https://codepen.io/{}"),
    ("Replit","https://replit.com/@{}"),("HackerOne","https://hackerone.com/{}"),
    ("Bugcrowd","https://bugcrowd.com/{}"),("Stack Overflow","https://stackoverflow.com/users/{}"),
    ("SourceForge","https://sourceforge.net/u/{}"),("Launchpad","https://launchpad.net/~{}"),
    ("Gitea","https://gitea.com/{}"),("Codeberg","https://codeberg.org/{}")]

def _check_sites(u,sites):
    def probe(item):
        n,tpl=item
        return (n,tpl.format(u)) if head_ok(tpl.format(u),t=7) else None
    out=[]
    with ThreadPoolExecutor(max_workers=10) as ex:
        for r in ex.map(probe,sites):
            if r: out.append(r)
    return out
def p_social_username(q):
    u=q.strip().lstrip("@"); found=_check_sites(u,GLOBAL_SITES)
    rows=[("Username",u),("Checked",len(GLOBAL_SITES)),("Found",len(found))]
    for n,url in found: rows.append((n,url))
    return {"rows":rows,"status":"ok" if found else "warn"}
def p_username_regional(q):
    u=q.strip().lstrip("@"); found=_check_sites(u,REGIONAL_SITES)
    rows=[("Username",u),("Checked",len(REGIONAL_SITES)),("Found",len(found))]
    for n,url in found: rows.append((n,url))
    return {"rows":rows,"status":"ok" if found else "warn"}
def p_username_dev(q):
    u=q.strip().lstrip("@"); found=_check_sites(u,DEV_SITES)
    rows=[("Username",u),("Checked",len(DEV_SITES)),("Found",len(found))]
    for n,url in found: rows.append((n,url))
    return {"rows":rows,"status":"ok" if found else "warn"}
def p_username_archives(q):
    u=q.strip().lstrip("@"); rows=[("Username",u)]
    try:
        j=get("https://archive.org/advancedsearch.php?q=%s&fl=identifier,title&rows=8&output=json"%up.quote(u),t=20)
        docs=j.get("response",{}).get("docs",[])
        rows.append(("Archive.org items",str(len(docs))))
        for d in docs: rows.append(("",d.get("title",d.get("identifier","?"))))
    except Exception as e: rows.append(("Archive error",str(e)))
    return {"rows":rows}
def p_footprint(q):
    rows=[("Identifier",q)]; hits=0
    if re.fullmatch(r"@?[a-zA-Z0-9_.]{2,30}",q):
        u=q.lstrip("@"); found=_check_sites(u,GLOBAL_SITES[:20])
        hits+=len(found); rows.append(("Social platforms",str(len(found))))
    if "@" in q:
        try:
            j=get("https://api.xposedornot.com/v1/check-email/"+up.quote(q))
            n=len(j.get("breaches",[])); rows.append(("Breaches",str(n))); hits+=n
        except Exception: pass
    try:
        ipaddress.ip_address(q)
        j=get("http://ip-api.com/json/%s?fields=proxy,hosting"%q)
        rows.append(("Proxy/VPN","YES" if j.get("proxy") else "no"))
        if j.get("proxy") or j.get("hosting"): hits+=1
    except Exception: pass
    rows.append(("Footprint score",str(hits)))
    return {"rows":rows,"status":"bad" if hits>8 else "warn" if hits>3 else "ok"}

# ═══════════════════════════════════════════════════════════════════════
#  PHONE
# ═══════════════════════════════════════════════════════════════════════
CC_MAP={"1":"US / Canada","7":"Russia / Kazakhstan","20":"Egypt","27":"South Africa",
    "30":"Greece","31":"Netherlands","32":"Belgium","33":"France","34":"Spain","36":"Hungary",
    "39":"Italy","40":"Romania","41":"Switzerland","43":"Austria","44":"United Kingdom",
    "45":"Denmark","46":"Sweden","47":"Norway","48":"Poland","49":"Germany","51":"Peru",
    "52":"Mexico","54":"Argentina","55":"Brazil","56":"Chile","57":"Colombia","58":"Venezuela",
    "60":"Malaysia","61":"Australia","62":"Indonesia","63":"Philippines","64":"New Zealand",
    "65":"Singapore","66":"Thailand","81":"Japan","82":"South Korea","84":"Vietnam","86":"China",
    "90":"Turkey","91":"India","92":"Pakistan","93":"Afghanistan","94":"Sri Lanka","95":"Myanmar",
    "98":"Iran","212":"Morocco","213":"Algeria","216":"Tunisia","218":"Libya","234":"Nigeria",
    "254":"Kenya","351":"Portugal","353":"Ireland","354":"Iceland","358":"Finland","370":"Lithuania",
    "371":"Latvia","372":"Estonia","380":"Ukraine","381":"Serbia","420":"Czechia","421":"Slovakia",
    "852":"Hong Kong","886":"Taiwan","880":"Bangladesh","960":"Maldives","961":"Lebanon",
    "962":"Jordan","963":"Syria","964":"Iraq","965":"Kuwait","966":"Saudi Arabia","971":"UAE",
    "972":"Israel","973":"Bahrain","974":"Qatar","977":"Nepal","994":"Azerbaijan","995":"Georgia",
    "998":"Uzbekistan"}
def p_phone(q):
    num=re.sub(r"[^\d+]","",q); rows=[("Number",num)]
    cc=None
    for code in sorted(CC_MAP.keys(),key=len,reverse=True):
        if num.startswith("+"+code): cc=code; break
    if cc:
        rows.append(("Country",CC_MAP.get(cc,"unknown (+%s)"%cc)))
        rows.append(("Country code","+"+cc))
    rows.append(("Subscriber digits",len(num.lstrip("+"))-(len(cc) if cc else 0)))
    rows.append(("E.164",num if num.startswith("+") else "+"+num))
    return {"rows":rows,"status":"ok"}
def p_phone_carrier(q):
    key=os.environ.get("NUMVERIFY_KEY")
    if not key:
        return {"rows":[("Needs setup","Set NUMVERIFY_KEY to unlock carrier lookup")],"status":"warn"}
    j=get("http://apilayer.net/api/validate?access_key=%s&number=%s"%(key,up.quote(q)))
    if not j.get("valid"): return {"rows":[("Result","invalid number")],"status":"bad"}
    return {"rows":[("Valid","yes"),("Country",j.get("country_name","?")),
                    ("Carrier",j.get("carrier","?")),("Line type",j.get("line_type","?"))],
            "status":"ok"}

# ── NEW: Phone intelligence ──
def p_veriphone(q):
    """Veriphone — free phone validation, 1,000 credits/month."""
    key=os.environ.get("VERIPHONE_KEY")
    if not key: return {"rows":[("Needs setup","Set VERIPHONE_KEY to unlock Veriphone")],"status":"warn"}
    try:
        j=get("https://api.veriphone.io/v2/verify?phone=%s&key=%s"%(up.quote(q),key),t=12)
        return {"rows":[("Valid","yes" if j.get("status")=="success" else "no"),
                        ("Number",j.get("phone","?")),
                        ("International",j.get("international_number","?")),
                        ("Local",j.get("local_number","?")),
                        ("Country",j.get("country","?")),
                        ("Country code",j.get("country_code","?")),
                        ("Carrier",j.get("carrier","?")),
                        ("Line type",j.get("phone_type","?")),
                        ("Region",j.get("region","?"))],
                "status":"ok" if j.get("status")=="success" else "warn"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_ipqs_phone(q):
    """IPQualityScore phone validation — free tier 5,000/mo."""
    key=os.environ.get("IPQS_KEY")
    if not key: return {"rows":[("Needs setup","Set IPQS_KEY to unlock IPQS phone check")],"status":"warn"}
    try:
        j=get("https://ipqualityscore.com/api/json/phone/%s/%s"%(key,up.quote(q)),t=12)
        return {"rows":[("Valid","yes" if j.get("valid") else "no"),
                        ("Active","yes" if j.get("active") else "no"),
                        ("Formatted",j.get("formatted","?")),
                        ("Country",j.get("country","?")),
                        ("Carrier",j.get("carrier","?")),
                        ("Line type",j.get("line_type","?")),
                        ("Fraud score",str(j.get("fraud_score","?"))),
                        ("Recent abuse","YES" if j.get("recent_abuse") else "no"),
                        ("Prepaid","YES" if j.get("prepaid") else "no"),
                        ("Risky","YES" if j.get("risky") else "no")],
                "status":"bad" if j.get("risky") or j.get("recent_abuse") else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}

# ═══════════════════════════════════════════════════════════════════════
#  PEOPLE  ← NEW CATEGORY
# ═══════════════════════════════════════════════════════════════════════
def p_genderize(q):
    """Genderize.io — predict gender from first name. Free tier 2,500 names/month."""
    name=q.strip().split()[0]
    try:
        j=get("https://api.genderize.io/?name="+up.quote(name),t=10)
        if not j.get("gender"): return {"rows":[("Result","no prediction")],"status":"ok"}
        return {"rows":[("Name",j.get("name","?")),
                        ("Gender",j.get("gender","?")),
                        ("Probability","%.1f%%"%(float(j.get("probability",0))*100)),
                        ("Sample size",str(j.get("count",0)))],
                "status":"ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_agify(q):
    """Agify.io — predict age from first name. Free tier 1,000 names/day."""
    name=q.strip().split()[0]
    try:
        j=get("https://api.agify.io/?name="+up.quote(name),t=10)
        if not j.get("age"): return {"rows":[("Result","no prediction")],"status":"ok"}
        return {"rows":[("Name",j.get("name","?")),
                        ("Predicted age",str(j.get("age","?"))),
                        ("Sample size",str(j.get("count",0)))],
                "status":"ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_nationalize(q):
    """Nationalize.io — predict nationality from first name. Free tier 1,000 names/day."""
    name=q.strip().split()[0]
    try:
        j=get("https://api.nationalize.io/?name="+up.quote(name),t=10)
        countries=j.get("country",[])
        if not countries: return {"rows":[("Result","no prediction")],"status":"ok"}
        rows=[("Name",j.get("name","?"))]
        for c in countries[:5]:
            rows.append((c.get("country_id","?"),"%.1f%%"%(float(c.get("probability",0))*100)))
        return {"rows":rows,"status":"ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_wikidata_person(q):
    """Wikidata — search for people, get Q-ID and description."""
    try:
        j=get("https://www.wikidata.org/w/api.php?action=wbsearchentities&search=%s&language=en&limit=8&format=json"%up.quote(q),t=12)
        hits=j.get("search",[])
        if not hits: return {"rows":[("Result","no Wikidata match")],"status":"ok"}
        rows=[("Matches",len(hits))]
        for h in hits[:8]:
            rows.append((h.get("label","?"),h.get("description","?")))
        return {"rows":rows,"status":"ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_wikipedia_person(q):
    """Wikipedia summary for a person name."""
    term=q.strip()
    try:
        j=get("https://en.wikipedia.org/api/rest_v1/page/summary/"+up.quote(term),t=12)
        return {"rows":[("Title",j.get("title","?")),
                        ("Description",j.get("description","?")),
                        ("Extract",(j.get("extract","") or "")[:600]),
                        ("URL",j.get("content_urls",{}).get("desktop",{}).get("page","?"))]}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_open_sanctions(q):
    """OpenSanctions — sanctions/PEP screening. Free for non-commercial use."""
    try:
        j=get("https://api.opensanctions.org/search/default?q="+up.quote(q)+"&limit=5",t=15)
        res=j.get("results",[])
        return {"rows":[("Matches",len(res))]+[(r.get("caption","?"),
                     ", ".join(r.get("datasets",[])[:3])) for r in res],
                "status":"bad" if res else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_ofac_sdn(q):
    """OFAC SDN — US Treasury sanctions screening. Free, no key."""
    try:
        j=get("https://api.ofac-api.com/v2/search?name="+up.quote(q),t=15)
        hits=j.get("results",[]) or j.get("data",[]) or []
        return {"rows":[("Matches",len(hits))]+[(h.get("name","?"),h.get("program","?")) for h in hits[:10]],
                "status":"bad" if hits else "ok"}
    except Exception as e:
        return {"rows":[("OFAC SDN","manual check recommended"),
                        ("URL","https://sanctionssearch.ofac.treas.gov/"),
                        ("Detail",str(e)[:120])],"status":"warn"}
def p_sec_edgar_person(q):
    """SEC EDGAR — search for person in SEC filings, insider trades, company officers."""
    try:
        j=get("https://efts.sec.gov/LATEST/search-index?q=%s&dateRange=custom&forms=4" % up.quote(q), t=12)
        hits=j.get("hits",{}).get("hits",[]) or []
        return {"rows":[("Form 4 filings",len(hits))]+[(h.get("_source",{}).get("display_names",["?"])[0],
                     h.get("_source",{}).get("file_date","?")) for h in hits[:10]],
                "status":"warn" if hits else "ok"}
    except Exception as e:
        # fallback to EDGAR full-text search
        try:
            t=get_text("https://efts.sec.gov/LATEST/search-index?q=%s" % up.quote(q),t=12)
            return {"rows":[("EDGAR","manual search recommended"),
                            ("URL","https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company="+up.quote(q)),
                            ("Detail",str(e)[:120])],"status":"warn"}
        except Exception:
            return {"rows":[("EDGAR","manual check recommended"),
                            ("URL","https://www.sec.gov/edgar/searchedgar/companysearch")],"status":"warn"}
def p_fec_search(q):
    """FEC — federal campaign finance contributions by donor name."""
    key=os.environ.get("FEC_API_KEY","DEMO_KEY")
    try:
        j=get("https://api.open.fec.gov/v1/schedules/schedule_a/?contributor_name=%s&api_key=%s&per_page=10&sort=-contribution_receipt_date"%(up.quote(q),key),t=15)
        results=j.get("results",[]) or []
        return {"rows":[("Contributions",len(results))]+[(r.get("contributor_name","?"),
                     "%s %s"%(r.get("contribution_receipt_amount","?"),r.get("contribution_receipt_date","?"))) for r in results[:10]],
                "status":"warn" if results else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_court_listener(q):
    """CourtListener — free US court opinions, cases, dockets."""
    key=os.environ.get("COURTLISTENER_KEY")
    if not key: return {"rows":[("Needs setup","Set COURTLISTENER_KEY to unlock CourtListener")],"status":"warn"}
    try:
        h={"Authorization":"Token "+key}
        j=get("https://www.courtlistener.com/api/rest/v4/search/?q=%s&type=o" % up.quote(q),h,t=15)
        results=j.get("results",[]) or []
        return {"rows":[("Court opinions",len(results))]+[(r.get("caseName","?"),
                     r.get("dateFiled","?")) for r in results[:10]],
                "status":"warn" if results else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_open_corporates(q):
    """OpenCorporates — search company officers by person name. Free tier, no key."""
    try:
        j=get("https://api.opencorporates.com/v0.4/officers/search?q="+up.quote(q),t=15)
        results=j.get("results",{}).get("officers",[]) or []
        return {"rows":[("Officer matches",len(results))]+[(r.get("officer",{}).get("name","?"),
                     r.get("officer",{}).get("company",{}).get("name","?")) for r in results[:10]],
                "status":"warn" if results else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_pipl(q):
    """Pipl — people search by name/email/phone/username. Requires API key."""
    key=os.environ.get("PIPL_KEY")
    if not key: return {"rows":[("Needs setup","Set PIPL_KEY to unlock Pipl")],"status":"warn"}
    try:
        payload={"name":{"first":q.split()[0],"last":" ".join(q.split()[1:]) if len(q.split())>1 else ""}}
        j=post_json("https://api.pipl.com/search/?key=%s"%key,payload,t=15)
        p=j.get("person")
        if not p: return {"rows":[("Result","no Pipl match")],"status":"ok"}
        names=p.get("names",[]) or []; emails=p.get("emails",[]) or []
        return {"rows":[("Name"," ".join(names[0].get("display","").split())) if names else "?",
                        ("Emails",", ".join(e.get("address","?") for e in emails[:5]))],
                "status":"warn"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_social_analyzer(q):
    """Social Analyzer style — check username across many platforms with rating."""
    u=q.strip().lstrip("@")
    # reuse the global sites list but with a different confidence approach
    found=_check_sites(u,GLOBAL_SITES[:20])
    rows=[("Username",u),("Platforms checked",str(len(GLOBAL_SITES[:20]))),
          ("Profiles found",str(len(found)))]
    for n,url in found: rows.append((n,url))
    conf=min(100,len(found)*10)
    rows.append(("Confidence","%d%%"%conf))
    return {"rows":rows,"status":"ok" if found else "warn"}
def p_whatsmyname(q):
    """WhatsMyName style — check username across community-validated sites."""
    u=q.strip().lstrip("@")
    # subset of high-quality platforms
    sites=[("Instagram","https://www.instagram.com/{}/"),
           ("Twitter/X","https://x.com/{}"),
           ("GitHub","https://github.com/{}"),
           ("Reddit","https://www.reddit.com/user/{}"),
           ("TikTok","https://www.tiktok.com/@{}"),
           ("YouTube","https://www.youtube.com/@{}"),
           ("Twitch","https://www.twitch.tv/{}"),
           ("Steam","https://steamcommunity.com/id/{}"),
           ("Pinterest","https://www.pinterest.com/{}"),
           ("Medium","https://medium.com/@{}")]
    found=_check_sites(u,sites)
    rows=[("Username",u),("Platforms checked",str(len(sites))),
          ("Profiles found",str(len(found)))]
    for n,url in found: rows.append((n,url))
    return {"rows":rows,"status":"ok" if found else "warn"}

# ═══════════════════════════════════════════════════════════════════════
#  THREAT INTEL
# ═══════════════════════════════════════════════════════════════════════
def p_cve(q):
    q=q.upper()
    v=get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+q)["vulnerabilities"][0]["cve"]
    m=(v.get("metrics",{}).get("cvssMetricV31") or v.get("metrics",{}).get("cvssMetricV40") or [{}])[0].get("cvssData",{})
    rows=[("Summary",next(d["value"] for d in v["descriptions"] if d["lang"]=="en")),
          ("Severity","%s %s"%(m.get("baseScore","?"),m.get("baseSeverity",""))),
          ("Published",v["published"][:10])]
    try:
        epss=get("https://api.first.org/data/v1/epss?cve="+q)["data"][0]
        rows.append(("EPSS exploit likelihood","%.1f%%"%(float(epss["epss"])*100)))
    except Exception: pass
    score=float(m.get("baseScore",0) or 0)
    return {"rows":rows,"status":"bad" if score>=9 else "warn" if score>=7 else "ok"}
def p_hashid(q):
    h=q.strip()
    kind={32:"MD5 / NTLM",40:"SHA-1",64:"SHA-256",128:"SHA-512"}.get(len(h),"unknown")
    return {"rows":[("Hash",h),("Length",str(len(h))),("Likely algorithm",kind)]}
def p_urlscan_search(q):
    d=host_of(q) or q
    try:
        j=get("https://urlscan.io/api/v1/search/?q=domain:"+up.quote(d)+"&size=10",t=20)
        results=j.get("results",[])
        rows=[("Scans found",str(len(results)))]
        for r in results[:10]:
            rows.append((r.get("page",{}).get("url","?"),
                         "%s | %s"%(r.get("task",{}).get("time","?")[:19],
                                    r.get("page",{}).get("ip","?"))))
        return {"rows":rows}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_otx_lookup(q):
    d=host_of(q) or q
    try:
        j=get("https://otx.alienvault.com/api/v1/indicators/domain/%s/general"%up.quote(d),t=20)
        pulses=j.get("pulse_info",{}).get("pulses",[])
        rows=[("Pulses",str(len(pulses))),("Reputation",str(j.get("reputation",0)))]
        for p in pulses[:10]: rows.append((p.get("name","?"),", ".join(p.get("tags",[])[:5])))
        return {"rows":rows,"status":"warn" if pulses else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_urlhaus(q):
    """URLhaus — recent malicious URLs for a host."""
    d=host_of(q) or q
    try:
        j=post_form("https://urlhaus-api.abuse.ch/v1/host/",{"host":d},t=20)
        urls=j.get("urls",[]) or []
        return {"rows":[("Query status",j.get("query_status","?")),
                        ("URLs seen",len(urls))]+[("",u.get("url","?")) for u in urls[:10]],
                "status":"bad" if urls else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_threatfox(q):
    """ThreatFox IOC search (by hash or domain)."""
    try:
        j=post_json("https://threatfox-api.abuse.ch/api/v1/",{"query":"search_ioc","search_term":q},t=20)
        if j.get("query_status")!="ok":
            return {"rows":[("Status",j.get("query_status","?"))],"status":"ok"}
        data=j.get("data",[])[:10]
        return {"rows":[("Hits",len(data))]+[(d.get("ioc","?"),d.get("threat_type","?")+" | "+d.get("malware","?")) for d in data],
                "status":"bad" if data else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_malwarebazaar(q):
    """MalwareBazaar hash lookup."""
    try:
        j=post_form("https://mb-api.abuse.ch/api/v1/",{"query":"get_info","hash":q},t=20)
        if j.get("query_status")!="ok":
            return {"rows":[("Status",j.get("query_status","?"))],"status":"ok"}
        d=j.get("data",[{}])[0]
        return {"rows":[("File name",d.get("file_name","?")),
                        ("File type",d.get("file_type","?")),
                        ("Signature",d.get("signature","?")),
                        ("First seen",d.get("first_seen","?")),
                        ("Tags",", ".join(d.get("tags",[]) or []))],
                "status":"bad"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}

# ═══════════════════════════════════════════════════════════════════════
#  CRYPTO
# ═══════════════════════════════════════════════════════════════════════
def p_crypto_eth(q):
    """Ethereum address balance + tx count (free, no key)."""
    try:
        bal=int(get("https://api.etherscan.io/api?module=account&action=balance&address=%s&tag=latest"%q,t=15).get("result","0"))
        txc=int(get("https://api.etherscan.io/api?module=account&action=txlist&address=%s&page=1&offset=1&sort=desc"%q,t=15).get("result",[]) and 1 or 0)
        return {"rows":[("Address",q),("Balance (wei)",str(bal)),
                        ("Balance (ETH)","%.6f"%(bal/1e18))],
                "status":"ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_crypto_btc(q):
    try:
        j=get("https://blockchain.info/rawaddr/"+q+"?limit=1",t=15)
        return {"rows":[("Address",j.get("address","?")),
                        ("Total received (sat)",str(j.get("total_received","?"))),
                        ("Total sent (sat)",str(j.get("total_sent","?"))),
                        ("Final balance (sat)",str(j.get("final_balance","?"))),
                        ("Transactions",str(j.get("n_tx","?")))],
                "status":"ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_sanctions(q):
    """Screening against OpenSanctions search (public, no key)."""
    try:
        j=get("https://api.opensanctions.org/search/default?q="+up.quote(q)+"&limit=5",t=15)
        res=j.get("results",[])
        return {"rows":[("Matches",len(res))]+[(r.get("caption","?"),
                     ", ".join(r.get("datasets",[])[:3])) for r in res],
                "status":"bad" if res else "ok"}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}

# ═══════════════════════════════════════════════════════════════════════
#  SEARCH
# ═══════════════════════════════════════════════════════════════════════
def p_wikipedia(q):
    term=q.lstrip("@") if q.startswith("@") else q
    try:
        j=get("https://en.wikipedia.org/api/rest_v1/page/summary/"+up.quote(term),t=12)
        return {"rows":[("Title",j.get("title","?")),("Description",j.get("description","?")),
                        ("Extract",(j.get("extract","") or "")[:600]),
                        ("URL",j.get("content_urls",{}).get("desktop",{}).get("page","?"))]}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_github_search(q):
    h={"Accept":"application/vnd.github+json"}
    tok=os.environ.get("GITHUB_TOKEN")
    if tok: h["Authorization"]="Bearer "+tok
    try:
        j=get("https://api.github.com/search/users?q="+up.quote(q)+"&per_page=10",h)
        rows=[("Total matches",str(j.get("total_count",0)))]
        for it in j.get("items",[])[:10]:
            rows.append((it.get("login","?"),it.get("html_url","?")))
        return {"rows":rows}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_github_code(q):
    h={"Accept":"application/vnd.github+json"}
    tok=os.environ.get("GITHUB_TOKEN")
    if tok: h["Authorization"]="Bearer "+tok
    else: return {"rows":[("Info","GITHUB_TOKEN not set — code search requires auth")],"status":"warn"}
    try:
        j=get("https://api.github.com/search/code?q="+up.quote(q)+"&per_page=5",h)
        rows=[("Total",str(j.get("total_count",0)))]
        for it in j.get("items",[])[:5]:
            rows.append((it.get("repository",{}).get("full_name","?"),it.get("html_url","?")))
        return {"rows":rows}
    except Exception as e: return {"rows":[("Error",str(e))],"status":"warn"}
def p_dork(q):
    """Build Google dorks for the target — returns URLs, does not execute."""
    t=q.strip()
    dorks=[
        ('site',f'site:{t}'),
        ('inurl:admin',f'site:{t} inurl:admin'),
        ('filetype:pdf',f'site:{t} filetype:pdf'),
        ('filetype:xlsx',f'site:{t} (filetype:xlsx OR filetype:csv)'),
        ('env',f'site:{t} (ext:env OR ext:log OR ext:bak)'),
        ('git',f'site:{t} (intitle:index.of ".git" OR ".env")'),
        ('panels',f'site:{t} (inurl:login OR inurl:dashboard OR inurl:portal)'),
        ('s3',f'site:s3.amazonaws.com "{t}"'),
        ('pastebin',f'site:pastebin.com "{t}"'),
        ('trello',f'site:trello.com "{t}"'),
        ('docs',f'site:docs.google.com "{t}"'),
        ('linkedin',f'site:linkedin.com/in "{t}"'),
        ('facebook',f'site:facebook.com "{t}"'),
        ('people',f'"{t}" (site:truepeoplesearch.com OR site:fastpeoplesearch.com OR site:whitepages.com)'),
        ('emails',f'"{t}" (site:pastebin.com OR site:ghostbin.com OR site:hastebin.com)'),
        ('credentials',f'"{t}" (ext:txt OR ext:log OR ext:sql) (password OR passwd OR pwd)'),
    ]
    rows=[("Dorks generated",len(dorks))]
    for name,d in dorks:
        url="https://www.google.com/search?q="+up.quote(d)
        rows.append((name,url))
    return {"rows":rows,"status":"ok"}
def p_reverse(q):
    la,lo=[float(x) for x in q.split(",")]
    j=get("https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=%s&lon=%s"%(la,lo))
    return {"rows":[("Address",j.get("display_name","nothing here")),
                    ("Country",j.get("address",{}).get("country","?")),
                    ("Postcode",j.get("address",{}).get("postcode","?"))],
            "geo":(la,lo,"Coordinates")}

# ─── register all ──────────────────────────────────────────────────────
register("dns","DNS records","A/AAAA/MX/NS/TXT/SOA/CNAME.","Domain",["domain","url"],p_dns)
register("certs","Certificate transparency","Hostnames in public TLS certs.","Domain",["domain"],p_certs,1.2)
register("crt_history","Cert issuer history","Issuer breakdown across CT.","Domain",["domain"],p_crt_history,0.7)
register("subdomains","Passive subdomains","HackerTarget host search.","Domain",["domain"],p_subdomains)
register("rdap","Domain registration","Registrar, dates, nameservers.","Domain",["domain"],p_rdap,1.2)
register("hosting","Hosting info","Where the server lives.","Domain",["domain","url"],p_hosting)
register("wayback","Archive history","Wayback closest snapshot.","Archive",["domain","url"],p_wayback,0.8)
register("wayback_cdx","Wayback CDX","Full capture list.","Archive",["domain","url"],p_wayback_cdx,0.9)
register("archive_today","archive.today","Isolated snapshot availability.","Archive",["domain","url"],p_archive_today,0.6)
register("emailsec","Email security","SPF / DMARC posture.","Domain",["domain","email"],p_emailsec)
register("headers","HTTP security headers","Response hardening check.","Domain",["domain","url"],p_headers)
register("robots","robots / security.txt","Crawler policy + disclosure.","Domain",["domain","url"],p_robots,0.6)
register("tech","Tech fingerprint","Server banner + CMS hints.","Domain",["domain","url"],p_tech,0.8)
register("mx_provider","Mail provider","Who delivers this domain's mail.","Domain",["domain","email"],p_mx_provider,0.8)
register("ipgeo","IP geolocation","City/region/country + ISP.","Network",["ip"],p_ipgeo)
register("iprdap","IP block ownership","Who the range belongs to.","Network",["ip"],p_iprdap)
register("asn","ASN overview","Holder + routing visibility.","Network",["ip","asn"],p_asn)
register("ip_abuse","Proxy / VPN / hosting","Anonymisation detection.","Network",["ip"],p_ip_abuse,1.2)
register("reverse_dns","Reverse DNS (PTR)","Hostname mapping to this IP.","Network",["ip"],p_reverse_dns,0.9)
register("shodan_idb","Shodan InternetDB","Free port + CVE snapshot.","Network",["ip"],p_shodan_idb,1.4)
register("greynoise","GreyNoise","Internet background noise check.","Network",["ip"],p_greynoise,1.3)
register("email_breach","Breach check","XposedOrNot public breach index.","Email",["email"],p_email_breach,1.4)
register("people_email","Email → accounts","Services registered on this email.","Email",["email"],p_people_email,1.2)
register("gravatar","Gravatar profile","Public Gravatar profile.","Email",["email"],p_gravatar)
register("email_disposable","Disposable check","Public disposable-domain blocklist.","Email",["email"],p_email_disposable)
register("email_mx","Mail deliverability","MX presence check.","Email",["email"],p_email_mx,0.8)
register("emailrep","EmailRep reputation","Risk signals, linked profiles, breach flags.","Email",["email"],p_emailrep,1.3)
register("hunter_io","Hunter.io","Professional email discovery.","Email",["email","domain"],p_hunter_io,1.0)
register("ipqs_email","IPQS email validation","Fraud score, disposability, abuse flags.","Email",["email"],p_ipqs_email,1.3)
register("breach_directory","BreachDirectory","Search public breaches by email.","Email",["email"],p_breach_directory,1.2)
register("hudson_rock_email","Hudson Rock infostealer","Was this email caught by infostealer malware?","Email",["email"],p_hudson_rock_email,1.5)
register("social_username","Global social hunt","One username, dozens of platforms.","Username",["username"],p_social_username,1.3)
register("username_regional","Regional platforms","VK, Weibo, Bilibili, Naver, Ameba, Xing…","Username",["username"],p_username_regional,1.1)
register("username_dev","Developer platforms","GitLab, HN, NPM, PyPI, Docker…","Username",["username"],p_username_dev)
register("username_archives","Archive presence","Archive.org traces.","Archive",["username"],p_username_archives,0.7)
register("footprint","Digital footprint score","How exposed an identifier is.","Username",["username","email","ip"],p_footprint,1.2)
register("phone","Phone number info","Country, region, E.164.","Phone",["phone"],p_phone)
register("phone_carrier","Phone carrier","Carrier + line type (Numverify).","Phone",["phone"],p_phone_carrier)
register("veriphone","Veriphone","Phone validation + carrier + line type.","Phone",["phone"],p_veriphone,1.1)
register("ipqs_phone","IPQS phone","Fraud score, abuse flags, line type.","Phone",["phone"],p_ipqs_phone,1.3)

# ── PEOPLE ──
register("genderize","Genderize.io","Predict gender from first name.","People",["name","username"],p_genderize,1.0)
register("agify","Agify.io","Predict age from first name.","People",["name","username"],p_agify,0.9)
register("nationalize","Nationalize.io","Predict nationality from first name.","People",["name","username"],p_nationalize,0.9)
register("wikidata_person","Wikidata search","Find people by name, get Q-ID + description.","People",["name","username"],p_wikidata_person,1.0)
register("wikipedia_person","Wikipedia summary","Background on notable people.","People",["name","username"],p_wikipedia_person,0.6)
register("open_sanctions","OpenSanctions","Sanctions / PEP screening.","People",["name","username","wallet"],p_open_sanctions,1.5)
register("ofac_sdn","OFAC SDN","US Treasury sanctions screening.","People",["name","username","wallet"],p_ofac_sdn,1.5)
register("sec_edgar_person","SEC EDGAR","Insider filings, company officers.","People",["name","username"],p_sec_edgar_person,1.1)
register("fec_search","FEC campaign finance","Political contributions by donor name.","People",["name","username"],p_fec_search,1.0)
register("court_listener","CourtListener","US court opinions, cases, dockets.","People",["name","username"],p_court_listener,1.2)
register("open_corporates","OpenCorporates","Company officer search by name.","People",["name","username"],p_open_corporates,1.1)
register("pipl","Pipl","People search by name/email/phone.","People",["name","email","phone"],p_pipl,1.4)
register("social_analyzer","Social Analyzer","Username across platforms with confidence.","People",["username","name"],p_social_analyzer,1.1)
register("whatsmyname","WhatsMyName","Community-validated username search.","People",["username","name"],p_whatsmyname,1.0)

register("cve","CVE details","NVD + EPSS exploit likelihood.","Threat",["cve"],p_cve,1.5)
register("hashid","Hash identification","Algorithm guess.","Threat",["hash"],p_hashid,0.8)
register("urlscan_search","urlscan.io search","Public scans of this domain.","Threat",["domain","url","ip"],p_urlscan_search,1.1)
register("otx_lookup","AlienVault OTX","Threat-intel pulses.","Threat",["domain","ip"],p_otx_lookup,1.2)
register("urlhaus","URLhaus","Malicious URL feed.","Threat",["domain","url"],p_urlhaus,1.2)
register("threatfox","ThreatFox","C2 IOC database.","Threat",["domain","ip","hash"],p_threatfox,1.3)
register("malwarebazaar","MalwareBazaar","Malware sample DB.","Threat",["hash"],p_malwarebazaar,1.3)
register("crypto_eth","Ethereum wallet","Balance + activity.","Crypto",["wallet"],p_crypto_eth,1.2)
register("crypto_btc","Bitcoin wallet","Balance + activity.","Crypto",["wallet"],p_crypto_btc,1.2)
register("sanctions","Sanctions screening","OpenSanctions check.","Threat",["username","domain","wallet"],p_sanctions,1.4)
register("wikipedia","Wikipedia summary","Background context.","Search",["username","domain","email","name"],p_wikipedia,0.5)
register("github_search","GitHub search","Users / orgs matching the identifier.","Search",["username","email","domain","name"],p_github_search,0.9)
register("github_code","GitHub code search","Code leaks referencing identifier.","Search",["username","email","domain","hash"],p_github_code,1.1)
register("dork","Dork builder","Pre-built dork URLs for the target.","Search",["domain","url","name","email"],p_dork,0.6)
register("reverse","Reverse geocode","Coordinates → address.","Geo",["coords"],p_reverse)

# ═══════════════════════════════════════════════════════════════════════
#  AI ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════
JOBS, JOBS_LOCK = {}, threading.Lock()
def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def _extract_entities(rows):
    ents,seen=[],set()
    for k,v in rows:
        v=str(v)
        for m in re.finditer(r"https?://[^\s,)>\]]+",v):
            key=("url",m.group(0))
            if key not in seen: seen.add(key); ents.append(key)
        for m in re.finditer(r"[\w.+-]+@[\w-]+(\.[\w-]+)+",v):
            key=("email",m.group(0).lower())
            if key not in seen: seen.add(key); ents.append(key)
        for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",v):
            key=("ip",m.group(0))
            if key not in seen: seen.add(key); ents.append(key)
        for m in re.finditer(r"(?<![\w.@])@([a-zA-Z0-9_.]{2,30})",v):
            key=("username",m.group(1))
            if key not in seen: seen.add(key); ents.append(key)
        for m in re.finditer(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b",v):
            key=("name",m.group(1))
            if key not in seen: seen.add(key); ents.append(key)
        for m in re.finditer(r"\+?\d[\d\s\-()]{6,20}\d",v):
            key=("phone",re.sub(r"[^\d+]","",m.group(0)))
            if key not in seen: seen.add(key); ents.append(key)
    return ents
def ai_investigate(q):
    jid=uuid.uuid4().hex; t=detect(q)
    mods=[m for m in FOR.get(t,[]) if MODS[m].get("ai")]
    with JOBS_LOCK:
        JOBS[jid]={"id":jid,"q":q,"type":t,"total":len(mods),"done":0,
                   "started":_now(),"results":{},"state":"running","log":[]}
    threading.Thread(target=_run_ai_job,args=(jid,q,t,mods),daemon=True).start()
    return jid
def _run_ai_job(jid,q,t,mods):
    job=JOBS[jid]
    job["log"].append("ARCHIVE // sector 7G // detected type = %s"%t)
    job["log"].append("selected %d modules"%len(mods))
    def run_one(mid):
        t0=time.time()
        try:
            r=MODS[mid]["fn"](q); r["ok"]=True
        except Exception as e:
            r={"ok":False,"error":"%s: %s"%(type(e).__name__,e),"status":"bad"}
        r["ms"]=int((time.time()-t0)*1000)
        return mid,r
    with ThreadPoolExecutor(max_workers=8) as ex:
        for f in as_completed([ex.submit(run_one,m) for m in mods]):
            mid,r=f.result(); job["results"][mid]=r; job["done"]+=1
            job["log"].append("✓ %s (%dms)"%(mid,r.get("ms",0)))
    all_ents,seen=[],set()
    for mid,r in job["results"].items():
        if not r.get("ok"): continue
        for kind,val in _extract_entities(r.get("rows",[])):
            if (kind,val.lower()) in seen: continue
            seen.add((kind,val.lower()))
            all_ents.append({"kind":kind,"value":val,"source":mid})
    scored=[]
    for mid,r in job["results"].items():
        base=MODS[mid]["weight"]*100
        if not r.get("ok"): score=0
        else:
            mult={"ok":1.0,"warn":0.75,"bad":0.9}.get(r.get("status","ok"),0.8)
            rows=r.get("rows",[])
            score=round(base*mult*min(1.0,0.5+0.05*len(rows)))
        scored.append({"module":mid,"label":MODS[mid]["label"],"category":MODS[mid]["category"],
                       "confidence":min(score,100),"status":r.get("status","ok"),
                       "ok":r.get("ok",False),"ms":r.get("ms",0)})
    scored.sort(key=lambda x:-x["confidence"])
    timeline=[{"ts":job["started"],"event":"investigation started",
               "detail":"type=%s modules=%d"%(t,len(mods))}]
    for mid,r in job["results"].items():
        timeline.append({"ts":_now(),"event":"module completed: %s"%MODS[mid]["label"],
                         "detail":"status=%s rows=%d"%(r.get("status","?"),len(r.get("rows",[])))})
    good=sum(1 for r in job["results"].values() if r.get("ok"))
    top=", ".join(s["label"] for s in scored[:3])
    summary=("ARCHIVE report — target %r classified as '%s'. %d modules dispatched, "
             "%d returned, %d failed, %d unique entities extracted. "
             "Strongest signals: %s."%(q,t,len(mods),good,len(mods)-good,len(all_ents),top))
    pivots,seen2=[],set()
    for mid,r in job["results"].items():
        for kind,val in _extract_entities(r.get("rows",[])):
            if val.lower()==str(q).lower() or val in seen2: continue
            seen2.add(val)
            pivots.append({"type":kind,"value":val,"why":"Found via %s"%mid})
    pivots=pivots[:15]
    graph={"nodes":[{"id":"root","label":q,"kind":"root"}]
           +[{"id":"cat-"+c,"label":c,"kind":"category"} for c in sorted({MODS[m]["category"] for m in mods})]
           +[{"id":"ent-%d"%i,"label":e["value"],"kind":e["kind"]} for i,e in enumerate(all_ents[:60])],
           "edges":[]}
    for m in mods: graph["edges"].append({"from":"root","to":"cat-"+MODS[m]["category"]})
    for i,e in enumerate(all_ents[:60]):
        graph["edges"].append({"from":"cat-"+MODS[e["source"]]["category"],"to":"ent-%d"%i})
    job.update(state="done",finished=_now(),summary=summary,entities=all_ents,
               confidence=scored,timeline=timeline,pivots=pivots,graph=graph)

# ═══════════════════════════════════════════════════════════════════════
#  STORE
# ═══════════════════════════════════════════════════════════════════════
CASES_FILE=os.path.join(DATA,"cases.json")
HIST_FILE=os.path.join(DATA,"history.json")
BOOK_FILE=os.path.join(DATA,"bookmarks.json")
def _load(p,d):
    try:
        with open(p,"r",encoding="utf-8") as f: return json.load(f)
    except Exception: return d
def _save(p,o):
    tmp=p+".tmp"
    with open(tmp,"w",encoding="utf-8") as f: json.dump(o,f,indent=2)
    os.replace(tmp,p)
def cases_all(): return _load(CASES_FILE,[])
def case_save(c):
    with DBL:
        cs=_load(CASES_FILE,[])
        for i,x in enumerate(cs):
            if x["id"]==c["id"]: cs[i]=c; break
        else: cs.append(c)
        _save(CASES_FILE,cs)
    return c
def case_delete(cid):
    with DBL: _save(CASES_FILE,[c for c in _load(CASES_FILE,[]) if c["id"]!=cid])
def history_add(e):
    with DBL:
        h=_load(HIST_FILE,[]); h.insert(0,e); _save(HIST_FILE,h[:500])
def history_all(): return _load(HIST_FILE,[])
def bookmarks_all(): return _load(BOOK_FILE,[])
def bookmark_add(b):
    with DBL:
        bm=_load(BOOK_FILE,[])
        if not any(x["id"]==b["id"] for x in bm): bm.insert(0,b)
        _save(BOOK_FILE,bm)
def bookmark_delete(bid):
    with DBL: _save(BOOK_FILE,[x for x in _load(BOOK_FILE,[]) if x["id"]!=bid])

def build_report(job_id,fmt="md"):
    with JOBS_LOCK: job=JOBS.get(job_id)
    if not job: raise ValueError("no such job")
    if job["state"]!="done": raise ValueError("job still running")
    if fmt=="json": return json.dumps(job,indent=2,default=str)
    L=["# NEUTRA · ARCHIVE // SECTOR 7G — Investigation Report\n",
       "- Target: `%s`"%job["q"],
       "- Type: `%s`"%job["type"],"- Started: %s"%job["started"],
       "- Finished: %s"%job.get("finished","?"),"- Modules: %d"%job["total"],"",
       "## Summary\n",job.get("summary",""),"","## Confidence-ranked findings\n",
       "| Module | Category | Status | Confidence | ms |","|---|---|---|---|---|"]
    for s in job.get("confidence",[]):
        L.append("| %s | %s | %s | %d | %d |"%(s["label"],s["category"],s["status"],s["confidence"],s["ms"]))
    L+=["","## Entities discovered\n"]
    for e in job.get("entities",[]):
        L.append("- **%s** `%s` _(source: %s)_"%(e["kind"],e["value"],e["source"]))
    L+=["","## Timeline\n"]
    for t in job.get("timeline",[]):
        L.append("- `%s` — %s (%s)"%(t["ts"],t["event"],t["detail"]))
    L+=["","## Suggested pivots\n"]
    for p in job.get("pivots",[]):
        L.append("- %s `%s` — %s"%(p["type"],p["value"],p["why"]))
    L+=["","## Raw module output\n"]
    for mid,r in job["results"].items():
        L.append("### %s — %s"%(mid,MODS[mid]["label"]))
        if not r.get("ok"): L.append("_Error: %s_"%r.get("error")); continue
        for k,v in r.get("rows",[]): L.append("- **%s:** %s"%(k or "·",v))
        L.append("")
    L.append("\n---\n_Generated by NEUTRA ARCHIVE 5.0 · SECTOR 7G — public data only._")
    return "\n".join(L)

# ═══════════════════════════════════════════════════════════════════════
#  HTTP
# ═══════════════════════════════════════════════════════════════════════
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _auth(self):
        if not AUTH: return True
        h=self.headers.get("Authorization","")
        if not h.startswith("Basic "): return False
        try:
            u,p=base64.b64decode(h[6:]).decode("utf-8").split(":",1)
        except Exception: return False
        return "%s:%s"%(u,p)==AUTH
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type, Authorization")
    def send(self,code,body,ctype="application/json",extra=None):
        if isinstance(body,bytes): b=body
        elif isinstance(body,str): b=body.encode("utf-8")
        else: b=json.dumps(body,default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type",ctype+"; charset=utf-8")
        self.send_header("Content-Length",str(len(b)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Archive","sector-7G")
        self._cors()
        if extra:
            for k,v in extra.items(): self.send_header(k,v)
        self.end_headers()
        self.wfile.write(b)
    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()
    def do_GET(self):
        u=up.urlparse(self.path); a={k:v[0] for k,v in up.parse_qs(u.query).items()}
        path,q=u.path,a.get("q","").strip()
        if path=="/healthz":
            return self.send(200,{"ok":True,"modules":len(MODS),"ts":_now(),"archive":"7G"})
        if not self._auth():
            return self.send(401,{"error":"auth required"},
                             extra={"WWW-Authenticate":'Basic realm="Neutra"'})
        if path=="/":
            ui=os.path.join(HERE,"index.html")
            if not os.path.isfile(ui): ui=os.path.join(HERE,"ui.html")
            if os.path.isfile(ui):
                with open(ui,"rb") as f: return self.send(200,f.read(),"text/html")
            return self.send(200,"<h1>index.html missing next to neutra.py</h1>","text/html")
        if path=="/api/detect":
            t=detect(q)
            return self.send(200,{"type":t,"mods":[
                {"id":m,"label":MODS[m]["label"],"why":MODS[m]["why"],
                 "category":MODS[m]["category"],"region":MODS[m]["region"]}
                for m in FOR.get(t,[])]})
        if path=="/api/catalog":
            return self.send(200,{"mods":[
                {"id":m["id"],"label":m["label"],"why":m["why"],"category":m["category"],
                 "region":m["region"],"applies":m["applies"],"weight":m["weight"]}
                for m in MODS.values()],"categories":CATS})
        if path=="/api/run":
            m=a.get("m"); t=detect(q)
            if m not in MODS or m not in FOR.get(t,[]):
                return self.send(400,{"ok":False,"error":"module not applicable"})
            try:
                t0=time.time(); r=MODS[m]["fn"](q)
                r["ok"]=True; r["status"]=r.get("status","ok")
                r["ms"]=int((time.time()-t0)*1000)
                history_add({"ts":_now(),"q":q,"type":t,"module":m,"status":r["status"]})
                return self.send(200,r)
            except ue.HTTPError as e:
                return self.send(200,{"ok":False,"error":"HTTP %s from source"%e.code})
            except Exception as e:
                return self.send(200,{"ok":False,"error":"%s: %s"%(type(e).__name__,e)})
        if path=="/api/ai/start":
            jid=ai_investigate(q)
            history_add({"ts":_now(),"q":q,"type":detect(q),"module":"AI","status":"running"})
            return self.send(200,{"job":jid})
        if path=="/api/ai/poll":
            jid=a.get("job","")
            with JOBS_LOCK: job=JOBS.get(jid)
            if not job: return self.send(404,{"error":"unknown job"})
            return self.send(200,{
                "id":job["id"],"q":job["q"],"type":job["type"],"state":job["state"],
                "done":job["done"],"total":job["total"],"started":job["started"],
                "log":job.get("log",[])[-30:],
                "summary":job.get("summary"),"entities":job.get("entities",[]),
                "confidence":job.get("confidence",[]),"timeline":job.get("timeline",[]),
                "pivots":job.get("pivots",[]),"graph":job.get("graph"),
                "raw":job.get("results",{}) if job["state"]=="done" else {}})
        if path=="/api/ai/report":
            try: text=build_report(a.get("job",""),a.get("fmt","md"))
            except Exception as e: return self.send(400,{"error":str(e)})
            ct="application/json" if a.get("fmt")=="json" else "text/markdown"
            fn="neutra_%s.%s"%(a.get("job","report")[:8],a.get("fmt","md"))
            return self.send(200,text,ct,{"Content-Disposition":'attachment; filename="%s"'%fn})
        if path=="/api/cases": return self.send(200,{"cases":cases_all()})
        if path=="/api/cases/save":
            try: case=json.loads(a.get("case","{}"))
            except Exception: return self.send(400,{"error":"invalid case payload"})
            if not case.get("id"): case["id"]=uuid.uuid4().hex[:10]
            if not case.get("created"): case["created"]=_now()
            case["updated"]=_now(); case_save(case)
            return self.send(200,{"ok":True,"case":case})
        if path=="/api/cases/delete":
            case_delete(a.get("id","")); return self.send(200,{"ok":True})
        if path=="/api/history": return self.send(200,{"history":history_all()})
        if path=="/api/bookmarks": return self.send(200,{"bookmarks":bookmarks_all()})
        if path=="/api/bookmarks/add":
            b={"id":uuid.uuid4().hex[:10],"ts":_now(),"value":a.get("value",""),
               "label":a.get("label",""),"type":a.get("type","unknown")}
            bookmark_add(b); return self.send(200,{"ok":True,"bookmark":b})
        if path=="/api/bookmarks/delete":
            bookmark_delete(a.get("id","")); return self.send(200,{"ok":True})
        self.send(404,{"error":"not found"})

if __name__=="__main__":
    print(BANNER)
    srv=http.server.ThreadingHTTPServer((HOST,PORT),H)
    print("  ARCHIVE: ONLINE  ·  SECTOR 7G  ·  http://%s:%d"%(HOST,PORT))
    print("  %d modules registered  ·  data: %s"%(len(MODS),DATA))
    print("  people modules: genderize, agify, nationalize, wikidata, opensanctions, ofac,")
    print("                  sec edgar, fec, courtlistener, opencorporates, pipl, social-analyzer")
    if AUTH: print("  HTTP Basic auth enabled")
    if "--no-browser" not in sys.argv and HOST in ("127.0.0.1","localhost","0.0.0.0"):
        threading.Timer(1,lambda:webbrowser.open("http://127.0.0.1:%d"%PORT)).start()
    try: srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  ARCHIVE: OFFLINE")