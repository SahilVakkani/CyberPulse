#!/usr/bin/env python3
"""CyberPulse collector.

Pulls security news, research blogs and threat-intel feeds into one JSON file
that the static website reads. Run it on a schedule (see .github/workflows).

Usage:
    python collector/collector.py --config collector/feeds.yml --out docs/data/news.json
    python collector/collector.py --demo      # no network, writes sample data
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import feedparser
import requests
import yaml

UA = "Mozilla/5.0 (compatible; CyberPulseBot/1.0)"
TIMEOUT = 20
KEEP_DAYS = 14
MAX_ITEMS = 1500
SNIPPET_LEN = 280

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Keyword rules that assign topics. They run on title + snippet.
_RULES = {
    "malware": r"malware|trojan|backdoor|infostealer|info-stealer|stealer|loader|botnet|\bRAT\b|rootkit|spyware|wiper|dropper|malicious (package|app|extension)",
    "ransomware": r"ransomware|extortion|lockbit|blackcat|alphv|akira|\bclop\b|ransom",
    "threat-hunting": r"threat hunt|hunting|detection engineering|detection rule|sigma rule|\byara\b|\bkql\b|splunk|sentinel|att&ck|attack technique",
    "vulnerabilities": r"cve-\d{4}-\d+|zero-day|0-day|vulnerabilit|exploit|patch tuesday|privilege escalation|remote code execution|security update",
    "cloud-identity": r"azure|entra|active directory|\baws\b|google cloud|oauth|okta|\biam\b|kubernetes|\bmfa\b|token theft|cloud",
    "dfir": r"forensic|incident response|\bdfir\b|memory analysis|volatility|post-incident|timeline analysis",
    "threat-actors": r"\bapt\d*\b|threat actor|nation-state|state-sponsored|lazarus|fancy bear|sandworm|scattered spider|lapsus|\bunc\d{3,4}\b|\bstorm-\d{4}\b|\bta\d{3}\b",
    "phishing": r"phishing|spearphish|smishing|vishing|business email compromise|\bbec\b|credential harvesting|social engineering",
}
TAG_RULES = {tag: re.compile(rx, re.I) for tag, rx in _RULES.items()}

TYPE_LABELS = {
    "news": "News",
    "vendor-research": "Vendor and research blogs",
    "government": "Government and CERT",
    "community": "Community and OSINT",
    "intel-feed": "Threat intel feeds and APIs",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(value: str | None, limit: int = SNIPPET_LEN) -> str:
    text = html.unescape(value or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rsplit(" ", 1)[0] + "…"
    return text


def safe_url(url: str | None) -> str:
    if not url:
        return ""
    return url if urlparse(url).scheme in ("http", "https") else ""


def homepage(url: str) -> str:
    parts = urlparse(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""


def title_key(title: str) -> str:
    return re.sub(r"[^a-z0-9]", "", title.lower())


def assign_tags(text: str, defaults: list[str]) -> list[str]:
    tags = list(defaults)
    for tag, rx in TAG_RULES.items():
        if tag not in tags and rx.search(text):
            tags.append(tag)
    return tags or ["general"]


def make_item(title, link, source, source_type, summary, published, defaults):
    title = clean_text(title, 200)
    link = safe_url(link)
    if not title or not link:
        return None
    summary = clean_text(summary)
    return {
        "id": hashlib.sha1(link.encode()).hexdigest()[:16],
        "title": title,
        "link": link,
        "source": source,
        "type": source_type,
        "summary": summary,
        "published": iso(published),
        "tags": assign_tags(f"{title} {summary}", defaults),
    }


def entry_date(entry) -> datetime:
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            return datetime(*parsed[:6], tzinfo=timezone.utc)
    return now_utc()


def fetch_bytes(url: str) -> bytes:
    if url.startswith("file://"):
        return Path(url[7:]).read_bytes()
    resp = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.content


def collect_feed(feed: dict):
    name, url = feed["name"], feed["url"]
    ftype = feed.get("type", "news")
    status = {"name": name, "type": ftype, "home": homepage(url), "status": "ok", "count": 0}
    items = []
    try:
        parsed = feedparser.parse(fetch_bytes(url))
        if not parsed.entries:
            raise ValueError("feed has no entries")
        cutoff = now_utc() - timedelta(days=KEEP_DAYS)
        for entry in parsed.entries:
            published = entry_date(entry)
            if published < cutoff:
                continue
            item = make_item(
                entry.get("title"), entry.get("link"), name, ftype,
                entry.get("summary") or entry.get("description"),
                published, feed.get("tags", []),
            )
            if item:
                items.append(item)
        status["count"] = len(items)
    except Exception as exc:  # one bad feed must not stop the run
        status.update(status="error", error=str(exc)[:160])
    return status, items


def collect_kev():
    status = {"name": "CISA Known Exploited Vulnerabilities", "type": "intel-feed",
              "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
              "status": "ok", "count": 0}
    out = []
    try:
        data = requests.get(KEV_URL, headers={"User-Agent": UA}, timeout=TIMEOUT).json()
        vulns = sorted(data.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)
        for v in vulns[:15]:
            out.append({
                "cve": v.get("cveID", ""),
                "vendor": clean_text(v.get("vendorProject"), 60),
                "product": clean_text(v.get("product"), 60),
                "name": clean_text(v.get("vulnerabilityName"), 120),
                "added": v.get("dateAdded", ""),
                "due": v.get("dueDate", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
            })
        status["count"] = len(out)
    except Exception as exc:
        status.update(status="error", error=str(exc)[:160])
    return status, out


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def collect_urlhaus():
    status = {"name": "abuse.ch URLhaus", "type": "intel-feed", "home": "https://urlhaus.abuse.ch",
              "status": "ok", "count": 0}
    key = os.environ.get("ABUSECH_API_KEY")
    if not key:
        status["status"] = "skipped (no API key)"
        return status, []
    out = []
    try:
        resp = requests.get(URLHAUS_URL, headers={"User-Agent": UA, "Auth-Key": key}, timeout=TIMEOUT)
        resp.raise_for_status()
        for u in resp.json().get("urls", [])[:15]:
            out.append({
                "indicator": defang(u.get("url", "")),
                "threat": clean_text(u.get("threat"), 40),
                "tags": [clean_text(t, 30) for t in (u.get("tags") or [])][:4],
                "added": clean_text(u.get("date_added"), 30),
                "source": "URLhaus",
            })
        status["count"] = len(out)
    except Exception as exc:
        status.update(status="error", error=str(exc)[:160])
    return status, out


def collect_otx():
    status = {"name": "AlienVault OTX", "type": "intel-feed", "home": "https://otx.alienvault.com",
              "status": "ok", "count": 0}
    key = os.environ.get("OTX_API_KEY")
    if not key:
        status["status"] = "skipped (no API key)"
        return status, []
    items = []
    try:
        since = iso(now_utc() - timedelta(days=3))
        resp = requests.get(OTX_URL, params={"limit": 20, "modified_since": since},
                            headers={"User-Agent": UA, "X-OTX-API-KEY": key}, timeout=TIMEOUT)
        resp.raise_for_status()
        for p in resp.json().get("results", []):
            published = datetime.fromisoformat(p["modified"].split(".")[0]).replace(tzinfo=timezone.utc)
            item = make_item(
                p.get("name"), f"https://otx.alienvault.com/pulse/{p.get('id')}",
                "AlienVault OTX", "intel-feed", p.get("description"), published, ["threat-actors"],
            )
            if item:
                items.append(item)
        status["count"] = len(items)
    except Exception as exc:
        status.update(status="error", error=str(exc)[:160])
    return status, items


def merge(existing: list[dict], fresh: list[dict]) -> list[dict]:
    cutoff = iso(now_utc() - timedelta(days=KEEP_DAYS))
    by_id = {i["id"]: i for i in existing if i.get("published", "") >= cutoff}
    for item in fresh:
        by_id[item["id"]] = item
    seen, merged = set(), []
    for item in sorted(by_id.values(), key=lambda i: i["published"], reverse=True):
        key = (item["source"], title_key(item["title"]))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged[:MAX_ITEMS]


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def run_demo(config: dict, out: Path) -> int:
    fixture = Path(__file__).parent / "tests" / "fixtures" / "demo_feed.xml"
    parsed = feedparser.parse(fixture.read_bytes())
    now = now_utc()
    items = []
    for n, entry in enumerate(parsed.entries):
        item = make_item(entry.get("title"), entry.get("link"), "Demo feed (sample data)", "news",
                         entry.get("summary"), now - timedelta(hours=3 * n + 1), [])
        if item:
            items.append(item)
    sources = [{"name": f["name"], "type": f.get("type", "news"), "home": homepage(f["url"]),
                "status": "pending", "count": 0} for f in config["feeds"]]
    for name, home in (("CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                       ("abuse.ch URLhaus", "https://urlhaus.abuse.ch"),
                       ("AlienVault OTX", "https://otx.alienvault.com")):
        sources.append({"name": name, "type": "intel-feed", "home": home, "status": "pending", "count": 0})
    kev = [{"cve": "CVE-2026-0001", "vendor": "Example", "product": "VPN appliance",
            "name": "Sample entry (demo data)", "added": iso(now)[:10], "due": iso(now + timedelta(days=21))[:10],
            "ransomware": False}]
    iocs = [{"indicator": "hxxps://malware-example[.]test/payload.exe", "threat": "malware_download",
             "tags": ["demo"], "added": iso(now), "source": "Demo"}]
    write_json(out, {"generated_at": iso(now), "demo": True, "items": items, "kev": kev, "iocs": iocs, "sources": sources})
    print(f"Demo data written to {out} ({len(items)} items)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="collector/feeds.yml")
    ap.add_argument("--out", default="docs/data/news.json")
    ap.add_argument("--demo", action="store_true", help="write sample data without touching the network")
    args = ap.parse_args()

    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    out = Path(args.out)
    if args.demo:
        return run_demo(config, out)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(collect_feed, config["feeds"]))
    sources = [s for s, _ in results]
    fresh = [i for _, items in results for i in items]

    kev_status, kev = collect_kev()
    ioc_status, iocs = collect_urlhaus()
    otx_status, otx_items = collect_otx()
    sources += [kev_status, ioc_status, otx_status]
    fresh += otx_items

    ok_feeds = sum(1 for s in sources if s["status"] == "ok")
    if ok_feeds == 0:
        print("Every source failed; keeping the previous data file.", file=sys.stderr)
        return 1

    existing = []
    previous = {}
    if out.exists():
        try:
            previous = json.loads(out.read_text(encoding="utf-8"))
            if not previous.get("demo"):
                existing = previous.get("items", [])
        except json.JSONDecodeError:
            pass
    # Keep the last good panels if an optional source is down or has no key today.
    if not kev and previous.get("kev") and not previous.get("demo"):
        kev = previous["kev"]
    if not iocs and previous.get("iocs") and not previous.get("demo"):
        iocs = previous["iocs"]

    items = merge(existing, fresh)
    write_json(out, {"generated_at": iso(now_utc()), "demo": False, "items": items,
                     "kev": kev, "iocs": iocs, "sources": sources})

    failed = [s["name"] for s in sources if s["status"] == "error"]
    print(f"{len(items)} items from {ok_feeds} sources; {len(failed)} failed")
    for s in sources:
        if s["status"] == "error":
            print(f"  FAILED {s['name']}: {s.get('error')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
