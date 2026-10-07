#!/usr/bin/env python3
"""NEUTRA OSINT 2.0 — run with: python neutra.py  (Python 3.8+, stdlib only)"""

import http.server, ipaddress, json, os, re, socket, sys, threading, time, webbrowser
import urllib.error as ue, urllib.parse as up, urllib.request as ur

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("NEUTRA_PORT", 8765))
UA   = "NeutraOSINT/2.0 (local ethical OSINT)"
TY   = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16}


# ---------------- rate limiter ----------------
class RateLimiter:
    def __init__(self):
        self.calls = {}
    def check(self, key, limit, window=60):
        now = time.time()
        self.calls.setdefault(key, [])
        self.calls[key] = [t for t in self.calls[key] if now - t < window]
        if len(self.calls[key]) >= limit:
            raise ValueError("rate limit reached for %s (%d/%ds)" % (key, limit, window))
        self.calls[key].append(now)

RL = RateLimiter()


# ---------------- http helpers ----------------
def get(url, h=None, t=15):
    req = ur.Request(url, headers={"User-Agent": UA, **(h or {})})
    with ur.urlopen(req, timeout=t) as r:
        return json.loads(r.read(3_000_000))

def get_text(url, h=None, t=15):
    req = ur.Request(url, headers={"User-Agent": UA, **(h or {})})
    with ur.urlopen(req, timeout=t) as r:
        return r.read(3_000_000).decode("utf-8", "replace")

def doh(name, typ):
    j = get("https://cloudflare-dns.com/dns-query?name=%s&type=%s"
            % (up.quote(name), typ), {"accept": "application/dns-json"})
    return [a["data"].strip('"') for a in j.get("Answer", []) if a.get("type") == TY[typ]]

def host_of(q):
    q = q.strip()
    if "@" in q and "://" not in q:
        return q.split("@")[-1].lower()
    return (up.urlparse(q if "://" in q else "//" + q).hostname or "").lower()

def reg_domain(h):
    return ".".join(h.split(".")[-2:])

def public_only(h):
    for i in socket.getaddrinfo(h, None):
        if not ipaddress.ip_address(i[4][0]).is_global:
            raise ValueError("blocked: target resolves to a private address")


# ---------------- input detection ----------------
def detect(q):
    q = q.strip()
    if not q or len(q) > 300:
        return "unknown"
    try:
        ipaddress.ip_address(q)
        return "ip"
    except ValueError:
        pass
    rules = [
        ("url",      r"https?://\S+"),
        ("email",    r"[\w.+-]+@[\w-]+(\.[\w-]+)+"),
        ("cve",      r"(?i)CVE-\d{4}-\d{4,}"),
        ("asn",      r"(?i)AS\d{1,10}"),
        ("hash",     r"(?i)([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})"),
        ("coords",   r"-?\d{1,2}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?"),
        ("phone",    r"\+?\d[\d\s\-()]{6,20}\d"),
        ("domain",   r"(?i)([a-z0-9-]{1,63}\.)+[a-z]{2,}"),
        ("username", r"@[a-zA-Z0-9_.]{2,30}"),
        ("username", r"[a-zA-Z0-9_]{2,30}"),
    ]
    for name, rx in rules:
        if re.fullmatch(rx, q):
            return name
    return "unknown"


# ======================================================================
# PULLERS
# ======================================================================

def ipinfo(ip):
    RL.check("ip-api", 45)
    j = get("http://ip-api.com/json/" + ip +
            "?fields=status,message,country,regionName,city,isp,org,as,lat,lon,query")
    if j.get("status") == "fail":
        raise ValueError(j.get("message", "lookup failed"))
    place = ", ".join(x for x in [j.get("city"), j.get("regionName"), j.get("country")] if x)
    return {"rows": [
        ("IP", j.get("query", ip)),
        ("Place", place),
        ("Network", j.get("isp") or j.get("org") or "?"),
        ("ASN", j.get("as", "?")),
    ], "geo": (j.get("lat"), j.get("lon"), "%s (%s)" % (ip, j.get("city", "?")))}


def p_dns(q):
    d = host_of(q)
    return {"rows": [(t, ", ".join(doh(d, t)) or "none") for t in TY]}


def p_certs(q):
    d = reg_domain(host_of(q))
    j = get("https://crt.sh/?q=%25." + up.quote(d) + "&output=json", t=30)
    names = sorted({x.lstrip("*.") for r in j for x in r["name_value"].split("\n") if x.endswith(d)})
    return {"rows": [("Hostnames found", len(names))] + [("", n) for n in names[:30]]}


def p_rdap(q):
    j = get("https://rdap.org/domain/" + reg_domain(host_of(q)))
    ev = {e["eventAction"]: e["eventDate"][:10] for e in j.get("events", [])}
    reg = "hidden"
    for e in j.get("entities", []):
        if "registrar" in e.get("roles", []):
            for v in e.get("vcardArray", [0, []])[1]:
                if v[0] == "fn":
                    reg = v[3]
    return {"rows": [
        ("Registrar", reg),
        ("Registered", ev.get("registration", "?")),
        ("Expires", ev.get("expiration", "?")),
        ("Name servers", ", ".join(n["ldhName"] for n in j.get("nameservers", [])) or "?"),
    ]}


def p_hosting(q):
    d = host_of(q)
    r = ipinfo(socket.gethostbyname(d))
    r["rows"].insert(0, ("Site", d))
    return r


def p_wayback(q):
    j = get("https://archive.org/wayback/available?url=" + up.quote(host_of(q)))
    c = j.get("archived_snapshots", {}).get("closest")
    return {"rows": [
        ("Closest snapshot", c["timestamp"][:8] if c else "none"),
        ("Link", c["url"] if c else "-"),
    ]}


def p_emailsec(q):
    d = reg_domain(host_of(q))
    spf = [t for t in doh(d, "TXT") if t.startswith("v=spf1")]
    dm  = [t for t in doh("_dmarc." + d, "TXT") if t.startswith("v=DMARC1")]
    pol = (re.search(r"p=(\w+)", dm[0]) or [0, "?"])[1] if dm else "missing"
    bad = not spf or pol in ("missing", "none")
    return {"rows": [("SPF", "present" if spf else "missing"),
                     ("DMARC policy", pol)],
            "status": "warn" if bad else "ok"}


def p_headers(q):
    d = host_of(q)
    public_only(d)
    try:
        h = ur.urlopen(ur.Request("https://" + d, headers={"User-Agent": UA}), timeout=12).headers
    except ue.HTTPError as e:
        h = e.headers
    want = ["strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy"]
    miss = [w for w in want if not h.get(w)]
    return {"rows": [(w, "present" if w not in miss else "MISSING") for w in want]
                     + [("Server banner", h.get("server", "hidden"))],
            "status": "ok" if len(miss) < 2 else "warn"}


def p_ipgeo(q):
    return ipinfo(q)


def p_iprdap(q):
    j = get("https://rdap.org/ip/" + q)
    return {"rows": [
        ("Owner block", j.get("name", "?")),
        ("Country", j.get("country", "?")),
        ("Range", "%s - %s" % (j.get("startAddress"), j.get("endAddress"))),
        ("Type", j.get("type", "?")),
    ]}


def p_asn(q):
    j = get("https://stat.ripe.net/data/as-overview/data.json?resource=" + q.upper())["data"]
    return {"rows": [("Holder", j.get("holder", "?")),
                     ("Announced", "yes" if j.get("announced") else "no")]}


def p_ip_abuse(q):
    RL.check("ip-api", 45)
    j = get("http://ip-api.com/json/" + q + "?fields=status,proxy,hosting,mobile,query")
    if j.get("status") == "fail":
        raise ValueError(j.get("message", "lookup failed"))
    return {"rows": [
        ("IP", q),
        ("Proxy/VPN", "YES" if j.get("proxy") else "no"),
        ("Hosting/Datacenter", "YES" if j.get("hosting") else "no"),
        ("Mobile network", "YES" if j.get("mobile") else "no"),
    ], "status": "warn" if j.get("proxy") or j.get("hosting") else "ok"}


def p_cve(q):
    q = q.upper()
    v = get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + q)["vulnerabilities"][0]["cve"]
    m = (v.get("metrics", {}).get("cvssMetricV31")
         or v.get("metrics", {}).get("cvssMetricV40") or [{}])[0].get("cvssData", {})
    rows = [
        ("Summary", next(d["value"] for d in v["descriptions"] if d["lang"] == "en")),
        ("Severity", "%s %s" % (m.get("baseScore", "?"), m.get("baseSeverity", ""))),
        ("Published", v["published"][:10]),
    ]
    try:
        rows.append(("Exploit likelihood", "%.1f%%" % (
            float(get("https://api.first.org/data/v1/epss?cve=" + q)["data"][0]["epss"]) * 100)))
    except Exception:
        pass
    score = float(m.get("baseScore", 0) or 0)
    return {"rows": rows, "status": "bad" if score >= 9 else "warn" if score >= 7 else "ok"}


def p_hashid(q):
    kind = {32: "MD5 or NTLM", 40: "SHA-1", 64: "SHA-256"}.get(len(q.strip()), "unknown")
    return {"rows": [("Likely type", kind), ("Length", len(q.strip()))]}


def p_reverse(q):
    la, lo = [float(x) for x in q.split(",")]
    j = get("https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=%s&lon=%s" % (la, lo))
    return {"rows": [
        ("Address", j.get("display_name", "nothing here")),
        ("Country", j.get("address", {}).get("country", "?")),
    ], "geo": (la, lo, "Coordinates")}


# ---------------- people ----------------
def p_people_name(q):
    key = os.environ.get("HEROHUNT_KEY")
    if not key:
        return {"rows": [("Needs setup",
                          "Set HEROHUNT_KEY env var (free at herohunt.ai)")], "status": "warn"}
    RL.check("herohunt", 10)
    j = get("https://api.herohunt.ai/v1/people/search?query=" + up.quote(q),
            {"x-api-key": key})
    people = j.get("data", [])[:10]
    rows = [("Results", len(people))]
    for p in people:
        rows.append((p.get("full_name", "?"),
                     "%s | %s | %s" % (p.get("job_title", "?"),
                                       p.get("company", {}).get("name", "?"),
                                       p.get("linkedin_url", "?"))))
    return {"rows": rows}


def p_people_email(q):
    import hashlib
    email = q.strip().lower()
    local = email.split("@")[0]
    rows = [("Email", email)]
    found = 0
    try:
        j = get("https://api.github.com/search/users?q=" + up.quote(local))
        if j.get("total_count", 0) > 0:
            rows.append(("GitHub", "found: " + j["items"][0]["html_url"]))
            found += 1
    except Exception:
        pass
    try:
        j = get("https://www.reddit.com/user/%s/about.json" % up.quote(local))
        if j.get("data", {}).get("name"):
            rows.append(("Reddit", "found: reddit.com/user/" + j["data"]["name"]))
            found += 1
    except Exception:
        pass
    gh = hashlib.md5(email.encode()).hexdigest()
    try:
        j = get("https://gravatar.com/%s.json" % gh)
        if j.get("entry"):
            rows.append(("Gravatar", "found: " + j["entry"][0].get("profileUrl", "?")))
            found += 1
    except Exception:
        pass
    rows.append(("Services found", str(found)))
    return {"rows": rows, "status": "warn" if found else "ok"}


def p_email_breach(q):
    RL.check("xon", 20)
    j = get("https://api.xposedornot.com/v1/check-email/" + up.quote(q.strip()))
    breaches = j.get("breaches", [])
    if not breaches:
        return {"rows": [("Result", "not found in any known breach")], "status": "ok"}
    rows = [("Breaches", len(breaches))]
    for b in breaches[:15]:
        rows.append((b, "leaked"))
    return {"rows": rows, "status": "bad"}


def p_password_check(q):
    import hashlib
    h = hashlib.sha1(q.encode()).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    try:
        text = get_text("https://api.pwnedpasswords.com/range/" + prefix)
        for line in text.splitlines():
            if line.startswith(suffix):
                count = int(line.split(":")[1])
                return {"rows": [("Result", "FOUND in %d breaches" % count),
                                 ("Advice", "change this password immediately")],
                        "status": "bad"}
        return {"rows": [("Result", "not found in breached password corpus")], "status": "ok"}
    except Exception as e:
        return {"rows": [("Error", str(e))], "status": "warn"}


# ---------------- phone ----------------
def p_phone(q):
    num = re.sub(r"[^\d+]", "", q)
    rows = [("Number", num)]
    cc_map = {"1": "US/Canada", "44": "UK", "49": "Germany", "33": "France",
              "91": "India", "86": "China", "81": "Japan", "61": "Australia",
              "7": "Russia/Kazakhstan", "55": "Brazil", "52": "Mexico",
              "34": "Spain", "39": "Italy", "46": "Sweden", "47": "Norway",
              "45": "Denmark", "358": "Finland", "48": "Poland"}
    cc = None
    for code in sorted(cc_map.keys(), key=len, reverse=True):
        if num.startswith("+" + code):
            cc = code
            break
    if cc:
        rows.append(("Country", cc_map.get(cc, "unknown (+%s)" % cc)))
    rows.append(("Length", len(num.lstrip("+"))))
    rows.append(("Note", "For carrier details, set NUMVERIFY_KEY and use phone_carrier."))
    return {"rows": rows, "status": "ok"}


def p_phone_carrier(q):
    key = os.environ.get("NUMVERIFY_KEY")
    if not key:
        return {"rows": [("Needs setup",
                          "Set NUMVERIFY_KEY (free at numverify.com)")], "status": "warn"}
    j = get("http://apilayer.net/api/validate?access_key=%s&number=%s" % (key, up.quote(q)))
    if not j.get("valid"):
        return {"rows": [("Result", "invalid number")], "status": "bad"}
    return {"rows": [
        ("Valid", "yes"),
        ("Country", j.get("country_name", "?")),
        ("Carrier", j.get("carrier", "?")),
        ("Line type", j.get("line_type", "?")),
    ], "status": "ok"}


# ---------------- social ----------------
MAIGRET_SITES = [
    ("Instagram", "https://www.instagram.com/{}/"),
    ("TikTok",    "https://www.tiktok.com/@{}"),
    ("Twitter/X", "https://x.com/{}"),
    ("LinkedIn",  "https://www.linkedin.com/in/{}"),
    ("Facebook",  "https://www.facebook.com/{}"),
    ("Snapchat",  "https://www.snapchat.com/add/{}"),
    ("Telegram",  "https://t.me/{}"),
    ("Reddit",    "https://www.reddit.com/user/{}"),
    ("YouTube",   "https://www.youtube.com/@{}"),
    ("GitHub",    "https://github.com/{}"),
    ("Steam",     "https://steamcommunity.com/id/{}"),
    ("Pinterest", "https://www.pinterest.com/{}"),
    ("Twitch",    "https://www.twitch.tv/{}"),
    ("Medium",    "https://medium.com/@{}"),
    ("DeviantArt","https://www.deviantart.com/{}"),
    ("Flickr",    "https://www.flickr.com/people/{}"),
    ("Tumblr",    "https://{}.tumblr.com/"),
    ("SoundCloud","https://soundcloud.com/{}"),
    ("VK",        "https://vk.com/{}"),
    ("Mastodon",  "https://mastodon.social/@{}"),
    ("Bluesky",   "https://bsky.app/profile/{}.bsky.social"),
    ("Threads",   "https://www.threads.net/@{}"),
    ("Roblox",    "https://www.roblox.com/user.aspx?username={}"),
    ("Xbox",      "https://xboxgamertag.com/search/{}"),
    ("PSN",       "https://psnprofiles.com/{}"),
]


def p_social_username(q):
    u = q.strip().lstrip("@")
    rows = [("Username", u), ("Sites checked", len(MAIGRET_SITES))]
    found = []
    for name, tpl in MAIGRET_SITES:
        url = tpl.format(u)
        try:
            req = ur.Request(url, headers={"User-Agent": UA}, method="HEAD")
            with ur.urlopen(req, timeout=8) as r:
                if r.status == 200:
                    found.append((name, url))
        except Exception:
            pass
    rows.append(("Found", str(len(found))))
    for name, url in found[:30]:
        rows.append((name, url))
    return {"rows": rows, "status": "ok" if found else "warn"}


def p_social_email(q):
    return p_people_email(q)


def p_discord_id(q):
    uid = q.strip()
    if not uid.isdigit():
        return {"rows": [("Error", "Discord IDs are numeric snowflakes")], "status": "bad"}
    try:
        j = get("https://discord.com/api/v10/users/" + uid)
        rows = [
            ("ID", j.get("id", "?")),
            ("Username", j.get("username", "?")),
            ("Display name", j.get("global_name", j.get("username", "?"))),
            ("Bot", "yes" if j.get("bot") else "no"),
            ("Avatar", "https://cdn.discordapp.com/avatars/%s/%s.png"
             % (uid, j.get("avatar", "")) if j.get("avatar") else "default"),
        ]
        return {"rows": rows, "status": "ok"}
    except ue.HTTPError as e:
        if e.code == 404:
            return {"rows": [("Result", "user not found (or private)")], "status": "warn"}
        raise


def p_gravatar(q):
    import hashlib
    gh = hashlib.md5(q.strip().lower().encode()).hexdigest()
    try:
        j = get("https://gravatar.com/%s.json" % gh)
        if not j.get("entry"):
            return {"rows": [("Result", "no Gravatar profile")], "status": "ok"}
        e = j["entry"][0]
        return {"rows": [
            ("Found", "yes"),
            ("Name", e.get("name", {}).get("formatted", "?")),
            ("About", e.get("aboutMe", "-")[:200]),
            ("Profile", e.get("profileUrl", "?")),
            ("Accounts", ", ".join(a.get("shortname", "?") for a in e.get("accounts", []))),
        ], "status": "warn"}
    except ue.HTTPError as e:
        if e.code == 404:
            return {"rows": [("Result", "no Gravatar profile")], "status": "ok"}
        raise


# ---------------- anti-doxx ----------------
def p_footprint(q):
    rows = [("Identifier", q)]
    hits = 0
    if re.fullmatch(r"@?[a-zA-Z0-9_.]{2,30}", q):
        u = q.lstrip("@")
        for name, tpl in MAIGRET_SITES[:15]:
            try:
                req = ur.Request(tpl.format(u), headers={"User-Agent": UA}, method="HEAD")
                with ur.urlopen(req, timeout=6) as r:
                    if r.status == 200:
                        hits += 1
            except Exception:
                pass
        rows.append(("Social platforms", str(hits)))
    if "@" in q:
        try:
            j = get("https://api.xposedornot.com/v1/check-email/" + up.quote(q))
            rows.append(("Breaches", str(len(j.get("breaches", [])))))
            hits += len(j.get("breaches", []))
        except Exception:
            pass
    try:
        ipaddress.ip_address(q)
        try:
            j = get("http://ip-api.com/json/" + q + "?fields=proxy,hosting")
            rows.append(("Proxy/VPN", "YES" if j.get("proxy") else "no"))
            rows.append(("Datacenter", "YES" if j.get("hosting") else "no"))
            if j.get("proxy") or j.get("hosting"):
                hits += 1
        except Exception:
            pass
    except ValueError:
        pass
    rows.append(("Footprint score", str(hits)))
    status = "bad" if hits > 5 else "warn" if hits > 2 else "ok"
    return {"rows": rows, "status": status}


# ======================================================================
# REGISTRY
# ======================================================================
MODS = {
    "dns":             ("DNS records", "Address book entries that say where a site and its email live.", p_dns),
    "certs":           ("Hidden subdomains", "Every hostname that ever got a public HTTPS certificate.", p_certs),
    "rdap":            ("Who registered it", "Registrar, creation and expiry dates.", p_rdap),
    "hosting":         ("Where it is hosted", "The server's country, city and network.", p_hosting),
    "wayback":         ("Old versions", "Whether the Internet Archive saved past copies.", p_wayback),
    "emailsec":        ("Email spoofing protection", "Can someone fake emails from this domain?", p_emailsec),
    "headers":         ("Website security check", "Checks the protective settings a website should send.", p_headers),
    "ipgeo":           ("Where is this IP", "Approximate location and network owner.", p_ipgeo),
    "iprdap":          ("Who owns this IP block", "The organisation the address range is assigned to.", p_iprdap),
    "asn":             ("Network owner", "The company that runs this network number.", p_asn),
    "ip_abuse":        ("Proxy / VPN / hosting check", "Detects anonymisation and datacenter IPs.", p_ip_abuse),
    "cve":             ("Vulnerability details", "What the flaw is, how severe, exploit likelihood.", p_cve),
    "hashid":          ("What kind of hash", "Guesses which algorithm made this fingerprint.", p_hashid),
    "reverse":         ("What is at these coordinates", "Turns coordinates into an address.", p_reverse),
    "people_name":     ("People search by name", "Search public profiles across LinkedIn, GitHub, StackOverflow.", p_people_name),
    "people_email":    ("Email-to-accounts", "Which services is this email registered on?", p_people_email),
    "email_breach":    ("Email breach check", "Free breach lookup via XposedOrNot (no key needed).", p_email_breach),
    "password_check":  ("Password exposure", "k-anonymity check against 900M+ breached passwords.", p_password_check),
    "phone":           ("Phone number lookup", "Country, carrier, line type via free public resources.", p_phone),
    "phone_carrier":   ("Phone carrier details", "Carrier and line type via Numverify free tier.", p_phone_carrier),
    "social_username": ("Social username hunt", "One username, checked across public sites.", p_social_username),
    "social_email":    ("Email-to-social", "Find social accounts linked to an email.", p_social_email),
    "discord_id":      ("Discord user lookup", "Public Discord user info from a user ID.", p_discord_id),
    "gravatar":        ("Gravatar profile", "Check if an email has a public Gravatar profile.", p_gravatar),
    "footprint":       ("Digital footprint score", "How many public platforms an identifier appears on.", p_footprint),
}

FOR = {
    "domain":   ["dns", "hosting", "certs", "rdap", "wayback", "emailsec", "headers", "footprint"],
    "url":      ["hosting", "headers", "wayback", "dns"],
    "ip":       ["ipgeo", "iprdap", "ip_abuse", "asn", "footprint"],
    "email":    ["people_email", "email_breach", "gravatar", "social_email", "password_check", "emailsec", "footprint"],
    "cve":      ["cve"],
    "asn":      ["asn"],
    "hash":     ["hashid"],
    "coords":   ["reverse"],
    "phone":    ["phone", "phone_carrier"],
    "username": ["social_username", "footprint"],
}


# ======================================================================
# SERVER
# ======================================================================
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        # bytes → as-is.  str → raw utf-8 (for HTML).  everything else → JSON.
        if isinstance(body, bytes):
            b = body
        elif isinstance(body, str):
            b = body.encode("utf-8")
        else:
            b = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.headers.get("Host", "").split(":")[0] not in ("127.0.0.1", "localhost"):
            return self.send(403, {"error": "forbidden"})
        u = up.urlparse(self.path)
        a = {k: v[0] for k, v in up.parse_qs(u.query).items()}
        q = a.get("q", "").strip()

        if u.path == "/":
            ui = os.path.join(HERE, "ui.html")
            if os.path.isfile(ui):
                with open(ui, "rb") as f:
                    return self.send(200, f.read(), "text/html")
            return self.send(200,
                "<h1>ui.html missing</h1><p>Place ui.html next to neutra.py and restart.</p>",
                "text/html")

        if u.path == "/api/detect":
            t = detect(q)
            return self.send(200, {"type": t, "mods": [
                {"id": m, "label": MODS[m][0], "why": MODS[m][1]} for m in FOR.get(t, [])
            ]})

        if u.path == "/api/run":
            m, t = a.get("m"), detect(q)
            if m not in MODS or m not in FOR.get(t, []):
                return self.send(400, {"ok": False, "error": "that puller doesn't apply to this input"})
            try:
                r = MODS[m][2](q)
                r.update(ok=True, status=r.get("status", "ok"))
                return self.send(200, r)
            except ue.HTTPError as e:
                return self.send(200, {"ok": False, "error": "the source answered HTTP %s" % e.code})
            except Exception as e:
                return self.send(200, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})

        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("NEUTRA OSINT 2.0 running at http://127.0.0.1:%d  (Ctrl+C to stop)" % PORT)
    if "--no-browser" not in sys.argv:
        threading.Timer(1, lambda: webbrowser.open("http://127.0.0.1:%d" % PORT)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass