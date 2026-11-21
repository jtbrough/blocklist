# blocklist

[![Build and publish](https://github.com/jtbrough/blocklist/actions/workflows/build.yml/badge.svg)](https://github.com/jtbrough/blocklist/actions/workflows/build.yml)

One definitive DNS blocklist, rebuilt every night from about two dozen upstream lists and published as a single stable
URL per format. It is de-duplicated, sorted, validated and **collapsed**: a domain is dropped when its parent is
already listed, because a blocked zone already covers its subdomains. Point every resolver you run at the same URL.

## Lists

Base URL: `https://jtbrough.github.io/blocklist/`

| File | Use it for | Entries | Download (gzip) |
|---|---|---|---|
| [`domains.txt`](https://jtbrough.github.io/blocklist/domains.txt) | Technitium, Pi-hole, anything that reads one domain per line | about 2.0 M | about 12 MB |
| [`adblock.txt`](https://jtbrough.github.io/blocklist/adblock.txt) | AdGuard Home and the AdGuard apps (`\|\|domain^` rules) | about 2.0 M | about 12 MB |
| [`domains-lite.txt`](https://jtbrough.github.io/blocklist/domains-lite.txt) | The same as `domains.txt`, ads and trackers only | about 380 k | about 3 MB |
| [`adblock-lite.txt`](https://jtbrough.github.io/blocklist/adblock-lite.txt) | The same as `adblock.txt`, ads and trackers only | about 380 k | about 3 MB |
| [`stats.json`](https://jtbrough.github.io/blocklist/stats.json) | Live counts per tier and per source | | |
| [`cosmetic.txt`](https://jtbrough.github.io/blocklist/cosmetic.txt) | uBlock Origin and AdGuard (Safari): hides page elements and blocks requests DNS cannot | hand-written rules | tiny |

- **Full** merges every source: ads, trackers, telemetry, malware, phishing, scams, stalkerware and crypto-miners.
- **Lite** keeps the ad, tracker and telemetry sources and leaves out the threat feeds. Use it where memory or
  bandwidth is tight, such as a phone app that loads the list itself.
- Files are plain text. The server compresses them in transit when the client asks for gzip, and answers `304` to a
  conditional request, so an unchanged day costs almost nothing. Do not point a client at a `.gz` file; there is none.
- A phone does not need a list at all if it uses your own resolver over DNS-over-HTTPS, DNS-over-TLS or a VPN.

## Add it to a resolver

| Resolver | Where | URL |
|---|---|---|
| **Technitium** | Settings > Blocking > Block List URLs (one per line), then Save and Update Now | `domains.txt` |
| **Pi-hole** | Adlists (Lists in v6): add the URL, then update gravity | `domains.txt` |
| **AdGuard Home** | Filters > DNS blocklists: add a custom list by URL | `adblock.txt` |
| **AdGuard for iOS / Android** | Add a custom filter by URL in the app's filter settings | `adblock-lite.txt` |

Use the lite file on a device that loads the list itself, and the full file on a server.

Technitium and Pi-hole accept `#` comments, so the header lines in `domains.txt` are harmless. Technitium re-downloads
the list on its update interval (24 hours by default) and uses `If-Modified-Since`.

## Browser filters

DNS removes hosts, not page elements. `cosmetic.txt` holds uBlock Origin / AdGuard rules for what DNS cannot: hiding a
module such as eBay Live, or blocking one URL path. Add it by URL: in uBlock Origin, Filter lists > Import; in AdGuard
for iOS, a custom filter. The build rejects a rule it cannot vouch for: unbalanced selectors, `{` style injection,
scriptlets (`+js(`) and procedural `#?#` rules.

## What the build does

`build.py` (Python 3.11 or newer, standard library only) reads `sources.toml` and, for each tier:

1. Downloads every source in parallel and parses it as `plain` (hosts lines or bare domains, CRLF tolerated) or
   `adblock` (only plain `||domain^` rules; exceptions, cosmetic rules and anything with modifiers are ignored).
2. Normalizes each name: lowercase, trailing dot removed, punycode for Unicode, and rejects anything that is not a
   valid hostname (IP addresses, single labels, bad characters, labels over 63 characters, names over 253).
3. Adds `block.txt`, removes `allow.txt` entries and their subdomains, and collapses subdomains of listed parents.
4. Sorts by reversed label so related names sit together, which also compresses better.
5. Validates `cosmetic.txt` and writes it with a header (see Browser filters), then writes `domains*.txt`, `adblock*.txt`, `stats.json` and a small `index.html`.

### What stops a bad publish

The build exits non-zero, and the previously published lists stay up, when:

- a source cannot be fetched, or parses to fewer domains than its `min_entries`;
- a tier shrinks by more than 15% against the lists now published (`--max-shrink`);
- any domain in `canary.txt`, or a domain under it, would be blocked.

CI emails you when a run fails.

## Files

| File | Purpose |
|---|---|
| `sources.toml` | Every upstream list: `name`, `url`, `format` (`plain` or `adblock`), `tiers`, `min_entries` |
| `allow.txt` | Domains to unblock; removed with their subdomains |
| `block.txt` | Extra domains to block in both tiers |
| `cosmetic.txt` | Browser filter rules, written by hand and published as is (validated, de-duplicated) |
| `canary.txt` | Domains that must never be blocked; the build fails if one is |
| `build.py` | The builder |
| `tests/` | Unit tests for parsing, normalization, collapsing, tiers and allow rules |

`allow.txt` has one limit: a flat list cannot unblock a subdomain whose parent is still blocked. The build prints a
warning for that case. Handle it with an allow rule in the resolver itself.

## Sources

Hagezi Multi PRO is the base; the Firebog "ticked" lists add ads, trackers and malware. The live count per source is in
`stats.json`.

| Tier | Sources |
|---|---|
| lite and full | Hagezi Multi PRO, KADhosts, W3KBL, AdAway, AdGuard DNS, Admiral, anudeepND adservers, EasyList, Yoyo adservers, hostsVN, EasyPrivacy, Prigent Ads, FadeMind 2o7Net, WindowsSpyBlocker, Frogeye first-party trackers |
| full only | Hagezi Threat Intelligence Feeds, FadeMind Spam, UncheckyAds and Risk, DandelionSprout Anti-Malware, Prigent Crypto, Phishing Army Extended, NoTrack malware, Spam404, stalkerware indicators, CyberHost malware |

Every source keeps its own licence and terms. This repository only republishes the merged domain names.

## Build it yourself

```
python3 build.py --out dist                 # downloads everything and writes dist/
python3 build.py --cache .cache --out dist  # reuses downloads between runs
python3 -m unittest discover -s tests       # tests, no network
```

## Publishing

The `Build and publish blocklist` workflow runs on every push, nightly at 03:17 UTC and on demand. Pushes to other
branches run the tests and the build only. A run from `main` also deploys `dist/` to GitHub Pages. The deploy sends the
whole site, so the lists and `stats.json` always match. No list is committed to git, so the history stays small.

To add a source, append a `[[source]]` block to `sources.toml` with a `min_entries` about 60% of its normal size, and
push.

## Licence

MIT. See `LICENSE`.
