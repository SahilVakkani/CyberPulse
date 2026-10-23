# CyberPulse

A cybersecurity news bulletin that pulls blogs, news, government advisories and threat-intel feeds into one site. Readers filter by topic (malware, ransomware, threat hunting, vulnerabilities, cloud and identity, DFIR, threat actors, phishing).

```
feeds.yml  ->  collector.py (runs every 30 min)  ->  docs/data/news.json  ->  static website
```

- `collector/feeds.yml`: the list of sources. Edit it to add or remove sources.
- `collector/collector.py`: fetches, cleans, deduplicates, tags and merges items.
- `docs/`: the website (plain HTML, CSS and JavaScript, no build step).
- `.github/workflows/update.yml`: runs the collector on a schedule and commits fresh data.

## Run it locally

```bash
pip install -r requirements.txt
python collector/collector.py --demo            # sample data, no network
python collector/collector.py                   # real run
cd docs && python -m http.server 8000           # open http://localhost:8000
```

## Put it online (free)

1. Create a GitHub repository and push this folder.
2. Settings, Pages: deploy from branch `main`, folder `/docs`.
3. Actions tab: run "Update news data" once by hand. After that it runs every 30 minutes.
4. Optional: add repository secrets `ABUSECH_API_KEY` and `OTX_API_KEY` to switch on the live malicious-URL panel and OTX pulses (both services give free keys).

## Sources

**News:** BleepingComputer, The Hacker News, Krebs on Security, SecurityWeek, Dark Reading, The Record, Schneier on Security

**Vendor and research blogs:** Microsoft Security Blog, Microsoft Security Response Center, Google Threat Intelligence (Mandiant), Google Project Zero, CrowdStrike, Unit 42 (Palo Alto Networks), Cisco Talos, SentinelOne Labs, Securelist (Kaspersky), ESET WeLiveSecurity, Check Point Research, Elastic Security Labs, Sophos News, Malwarebytes Labs, Red Canary, The DFIR Report

**Government and CERT:** CISA Cybersecurity Advisories, NCSC UK

**Community and OSINT:** SANS Internet Storm Center, Reddit r/netsec, Reddit r/blueteamsec

**Threat intel feeds and APIs:** CISA Known Exploited Vulnerabilities (no key needed), abuse.ch URLhaus (free key), AlienVault OTX (free key)

## How topics are assigned

Each item gets the default topics of its source plus any topic whose keywords appear in its title or summary. The rules are in `_RULES` at the top of `collector.py`. Tune them as you see misclassified items.

## Things to know

- Feed URLs change. If a source shows "error" in the Sources section of the site, find its current feed URL and update `feeds.yml`.
- The collector keeps 14 days of history and never overwrites the data file if every source fails.
- CERT-In and a few other sources do not publish a stable RSS feed. Add them if you find one, or write a small scraper.
- The site shows only headlines and short snippets with a link to the publisher. Do not republish full articles. Check each source's terms before commercial use.
- Malicious URLs from URLhaus are defanged before they reach the page.

## Ideas for next steps

- Email or Telegram digest of the day's top items per topic.
- Per-topic RSS output so others can subscribe to your filtered feeds.
- An "Indicators" page with downloadable IOC lists.
- AI-assisted tagging and a daily summary.
