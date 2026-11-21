#!/usr/bin/env python3
import argparse, hashlib, re, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import requests

SCRIPT_DIR = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
REQ = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9", "Accept": "text/html"}
STATUS_MAP = {"a": "alive", "d": "dead", "b": "blocked", "e": "error"}
SVC_LABEL = {
    "netflix": "Netflix",
    "disney": "Disney",
    "prime": "Prime",
    "dazn": "DAZN",
    "hulu": "Hulu",
    "paramount": "Paramount",
}

SERVICES = {
    "netflix": {
        "url": "https://www.netflix.com/browse",
        "need": {"NetflixId", "SecureNetflixId"},
        "alive": ('"profiles"', "profile-avatar", '"profileName"'),
        "login": ("/login", "signup"),
        "country": r'"countryOfSignup":"([A-Z]{2})"',
        "plan": [r'"memberPlan":"([^"]+)"', r'"planName":"([^"]+)"'],
        "hint": ("netflix",),
    },
    "disney": {
        "url": "https://www.disneyplus.com/home",
        "need": set(),
        "alive": ("disneyplus", "profile", "avatar"),
        "login": ("/login", "signup", "identity"),
        "country": r'"countryCode":"([A-Z]{2})"',
        "plan": [r'"productName":"([^"]+)"'],
        "hint": ("disney", "bam.pa"),
    },
    "prime": {
        "url": "https://www.primevideo.com/",
        "need": set(),
        "alive": ("prime-video", "pv-nav", '"isPrime"'),
        "login": ("/ap/signin", "signin"),
        "country": r'"currentTerritory":"([A-Z]{2})"',
        "plan": [r'"isPrime":(true)'],
        "hint": ("primevideo", "amazon", "at-main"),
    },
    "dazn": {
        "url": "https://www.dazn.com/home",
        "need": set(),
        "alive": ("dazn", "entitlement", "subscription"),
        "login": ("/signin", "/login"),
        "country": r'"country":"([A-Z]{2})"',
        "plan": [r'"tier":"([^"]+)"', r'"productName":"([^"]+)"'],
        "hint": ("dazn",),
    },
    "hulu": {
        "url": "https://www.hulu.com/account",
        "need": set(),
        "alive": ("hulu", "subscription", "profile"),
        "login": ("/login", "signin"),
        "country": r'"country":"([A-Z]{2})"',
        "plan": [r'"planName":"([^"]+)"'],
        "hint": ("hulu",),
    },
    "paramount": {
        "url": "https://www.paramountplus.com/account/",
        "need": set(),
        "alive": ("paramount", "subscription", "profile"),
        "login": ("/login", "signin"),
        "country": r'"country":"([A-Z]{2})"',
        "plan": [r'"planName":"([^"]+)"'],
        "hint": ("paramount", "cbs"),
    },
}


def load_cookies(path):
    """Load cookies from a Netscape-format file.
    Supports multiple independent cookie sets in one file
    (separated by blank lines or comment blocks).
    Returns list of (jar, cookie_text) or empty list on error.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return [], str(e)

    sets = []
    current_jar = []
    current_out = []
    has_cookies = False

    def flush():
        nonlocal current_jar, current_out, has_cookies
        if current_jar:
            text = "\n".join(current_out) + ("\n" if current_out else "")
            sets.append((current_jar[:], text))
            current_jar = []
            current_out = []
            has_cookies = False

    for line in lines:
        s = line.strip()
        if not s:
            if has_cookies:
                flush()
            continue
        if s.startswith("#"):
            if has_cookies:
                flush()
            continue
        f = s.split("\t")
        if len(f) < 7:
            continue
        try:
            exp = int(float(f[4])) if f[4] not in ("", "0") else 0
        except ValueError:
            exp = 0
        current_jar.append(
            {
                "name": f[5].strip(),
                "value": "".join(f[6:]).strip(),
                "domain": f[0].strip(),
                "path": f[2].strip(),
                "secure": f[3].strip().upper() == "TRUE",
                "expires": exp,
            }
        )
        current_out.append(
            "\t".join(x.strip() for x in f[:6]) + "\t" + "".join(f[6:]).strip()
        )
        has_cookies = True

    flush()
    return sets, None


def expiry_label(jar):
    now = int(datetime.now(timezone.utc).timestamp())
    best = max((c.get("expires") or 0) for c in jar) if jar else 0
    if best <= 0:
        return "session"
    left = best - now
    if left <= 0:
        return "expired"
    return f"{left // 86400}d"


def fingerprint(jar):
    keys = ("NetflixId", "SecureNetflixId", "SID", "at-main", "session-token", "bam.pa")
    parts = sorted(f"{c['name']}={c['value']}" for c in jar if c["name"] in keys)
    if not parts:
        parts = sorted(f"{c['name']}={c['value'][:16]}" for c in jar[:6])
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def session(jar, proxy=None):
    s = requests.Session()
    s.headers.update(REQ)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    for c in jar:
        s.cookies.set(
            c["name"],
            c["value"],
            domain=c["domain"],
            path=c["path"],
            secure=c["secure"],
        )
    return s


def grab(pat, text):
    m = re.search(pat, text)
    return m.group(1) if m else ""


def detect(jar):
    blob = " ".join((c["name"] + " " + c["domain"]).lower() for c in jar)
    for name, cfg in SERVICES.items():
        if any(h in blob for h in cfg["hint"]):
            return name
    return "netflix"


def check_one(item, service, retries=2, timeout=25, proxy=None, delay=0.0):
    """item is dict with path, source, jar, cookie_text, idx"""
    if delay:
        time.sleep(delay)
    path = item["path"]
    jar = item["jar"]
    cookie_text = item["cookie_text"]
    rec = {
        "source": item["source"],
        "path": str(path),
        "service": service,
        "verdict": "",
        "detail": "",
        "country": "",
        "plan": "",
        "expiry": "",
        "cookie_text": cookie_text or "",
    }
    if not jar:
        return {**rec, "verdict": "dead", "detail": "no cookie"}

    rec["expiry"] = expiry_label(jar)
    if rec["expiry"] == "expired":
        return {**rec, "verdict": "dead", "detail": "expired"}

    if service == "auto":
        service = detect(jar)
        rec["service"] = service
    cfg = SERVICES.get(service) or SERVICES["netflix"]

    if cfg["need"] and not ({c["name"] for c in jar} & cfg["need"]):
        return {**rec, "verdict": "dead", "detail": "missing key cookie"}

    for attempt in range(retries + 1):
        try:
            r = session(jar, proxy).get(
                cfg["url"], timeout=timeout, allow_redirects=False
            )
        except requests.RequestException as e:
            rec.update(verdict="error", detail=type(e).__name__)
            time.sleep(1.5 * (attempt + 1))
            continue

        code = r.status_code
        if code in (429, 403):
            rec.update(verdict="blocked", detail=f"HTTP {code}")
            time.sleep(2.5 * (attempt + 1))
            continue
        if code in (301, 302, 303, 307, 308):
            loc = (r.headers.get("Location") or "").lower()
            dead = any(x in loc for x in cfg["login"])
            return {
                **rec,
                "verdict": "dead",
                "detail": "login redirect" if dead else "redirect",
            }
        if code >= 500:
            rec.update(verdict="error", detail=f"HTTP {code}")
            time.sleep(1.5 * (attempt + 1))
            continue
        if code != 200:
            return {**rec, "verdict": "dead", "detail": f"HTTP {code}"}

        body = r.text
        if not any(m in body for m in cfg["alive"]):
            return {**rec, "verdict": "dead", "detail": "no login mark"}

        plan = ""
        for p in cfg.get("plan") or []:
            plan = grab(p, body)
            if plan:
                break
        if plan == "true":
            plan = "Prime"

        rec.update(
            verdict="alive",
            detail="ok",
            country=grab(cfg["country"], body) if cfg.get("country") else "",
            plan=plan,
        )
        return rec

    return {**rec, "verdict": rec["verdict"] or "error"}


def collect(targets):
    """Collect cookie items. Each item is one independent cookie set.
    Files containing multiple sets (separated by blank lines / comments)
    are automatically split into one item per set.
    """
    items, seen_files = [], set()
    for raw in targets:
        p = Path(raw)
        if not p.exists():
            print("[warn] not found:", raw, file=sys.stderr)
            continue
        found = [p.resolve()] if p.is_file() else sorted(p.rglob("*.txt"))
        for f in found:
            if f.suffix.lower() != ".txt" or f in seen_files:
                continue
            seen_files.add(f)
            sets, err = load_cookies(f)
            if err:
                # keep a placeholder so error is reported
                items.append(
                    {
                        "path": f,
                        "source": f.name,
                        "jar": [],
                        "cookie_text": "",
                        "idx": 0,
                    }
                )
                continue
            if not sets:
                items.append(
                    {
                        "path": f,
                        "source": f.name,
                        "jar": [],
                        "cookie_text": "",
                        "idx": 0,
                    }
                )
                continue
            multi = len(sets) > 1
            for i, (jar, text) in enumerate(sets):
                src = f.name if not multi else f"{f.stem}_{i+1}{f.suffix}"
                items.append(
                    {
                        "path": f,
                        "source": src,
                        "jar": jar,
                        "cookie_text": text,
                        "idx": i,
                    }
                )
    return items


def dedupe(items):
    kept, seen, skipped = [], set(), 0
    for item in items:
        jar = item.get("jar") or []
        if not jar:
            kept.append(item)
            continue
        fp = fingerprint(jar)
        if fp in seen:
            skipped += 1
            continue
        seen.add(fp)
        kept.append(item)
    return kept, skipped


def safe(s, fb="XX"):
    s = re.sub(r'[\\/:*?"<>|\s]+', "_", (s or "").strip())
    return s[:32] if s else fb


def make_name(rec):
    # JP_Netflix_a1b2c3d4e5f6.txt
    cc = safe(rec.get("country"), "XX")
    svc = SVC_LABEL.get(rec.get("service") or "", rec.get("service") or "Unknown")
    uid = uuid.uuid4().hex[:12]
    return f"{cc}_{svc}_{uid}.txt"


def main():
    ap = argparse.ArgumentParser(description="Streaming Cookie Checker")
    ap.add_argument("targets", nargs="+")
    ap.add_argument(
        "-s",
        default="auto",
        choices=["auto", "netflix", "disney", "prime", "dazn", "hulu", "paramount"],
    )
    ap.add_argument("-w", type=int, default=6)
    ap.add_argument("-t", type=int, default=25)
    ap.add_argument("-p", default=None)
    ap.add_argument(
        "-r", default="a", help="status to save: a/d/b/e (default: a = alive only)"
    )
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--no-dedupe", action="store_true")
    ap.add_argument("--retries", type=int, default=2, help=argparse.SUPPRESS)
    args = ap.parse_args()

    want = {STATUS_MAP[c] for c in re.findall(r"[adbe]", args.r.lower())} or {"alive"}
    items = collect(args.targets)
    if not items:
        sys.exit("no .txt files")

    skipped = 0
    if not args.no_dedupe:
        items, skipped = dedupe(items)

    out = SCRIPT_DIR / "result"
    out.mkdir(parents=True, exist_ok=True)

    print("=" * 52)
    print("  Streaming Cookie Checker")
    print("=" * 52)
    print(f"  service : {args.s}")
    print(
        f"  cookies : {len(items)}"
        + (f"  (dup skipped: {skipped})" if skipped else "")
    )
    print(f"  workers : {args.w}   delay: {args.delay}s")
    print(f"  export  : {', '.join(sorted(want))}")
    print("=" * 52)

    results, done = [], 0

    def job(item):
        return check_one(item, args.s, args.retries, args.t, args.p, args.delay)

    with ThreadPoolExecutor(max_workers=args.w) as ex:
        futs = {ex.submit(job, item): item for item in items}
        for fut in as_completed(futs):
            rec = fut.result()
            results.append(rec)
            done += 1
            mark = {
                "alive": "OK ",
                "dead": "-- ",
                "blocked": "BLK",
                "error": "ERR",
            }.get(rec["verdict"], "??")
            extra = ""
            if rec["verdict"] == "alive":
                extra = f"  {rec['country']} {rec['plan']} exp:{rec['expiry']}"
            print(
                f"  {done:>3}/{len(items)}  [{mark}] {(rec.get('service') or args.s):<8}  "
                f"{rec['source'][:28]:<28}  {rec['detail']}{extra}"
            )

    # result / Netflix / JP_Netflix_uuid.txt
    moved = {}
    for r in results:
        if r["verdict"] not in want:
            continue
        svc_key = r.get("service") or args.s
        label = SVC_LABEL.get(svc_key, svc_key.capitalize())
        dest = out / label
        dest.mkdir(parents=True, exist_ok=True)
        name = make_name(r)
        target = dest / name
        n = 1
        while target.exists():
            target = dest / f"{name[:-4]}_{n}.txt"
            n += 1
        target.write_text(r.get("cookie_text") or "", encoding="utf-8")
        moved[label] = moved.get(label, 0) + 1

    cnt = {}
    for r in results:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1

    print()
    print("=" * 52)
    print("  SUMMARY")
    print("=" * 52)
    for k in ("alive", "dead", "blocked", "error"):
        print(f"  {k:<10}: {cnt.get(k, 0)}")
    if skipped:
        print(f"  duplicates: {skipped}")
    if moved:
        print("-" * 52)
        for k, n in sorted(moved.items()):
            print(f"  saved {k:<16}: {n}")
    if cnt.get("blocked"):
        print("\n  tip: use -w 4 --delay 0.5 if many blocked")
    print("=" * 52)


if __name__ == "__main__":
    main()
