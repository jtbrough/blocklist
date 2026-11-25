#!/usr/bin/env python3
"""Build one de-duplicated DNS blocklist from the sources in sources.toml.

Outputs (in --out, default dist/): domains.txt and adblock.txt (full tier), domains-lite.txt and
adblock-lite.txt (lite tier), stats.json, index.html. See README.md.
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import html
import ipaddress
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
ADBLOCK_RULE = re.compile(r"\|\|([A-Za-z0-9._-]+)\^(?:\$important)?")
NOT_HOSTS = {"localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}
USER_AGENT = "blocklist-builder/1.0"


def normalize(name):
    """Lowercase, punycode and validate a hostname; None if it is not a blockable domain name."""
    name = name.strip().lower().rstrip(".")
    if not name or name in NOT_HOSTS:
        return None
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(name) > 253:
        return None
    labels = name.split(".")
    if len(labels) < 2 or labels[-1].isdigit():  # single label, or an IPv4 literal
        return None
    if not all(LABEL.match(label) for label in labels):
        return None
    return name


def is_ip(token):
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def parse(text, fmt):
    """Return (domains, rejected line count) for a source: "adblock" (||domain^) or "plain" (hosts or bare domains)."""
    out, rejected = set(), 0
    for line in text.splitlines():
        line = line.strip().replace("\r", "")
        if not line or line[0] in "#!":
            continue
        if fmt == "adblock":
            m = ADBLOCK_RULE.fullmatch(line)
            name = normalize(m.group(1)) if m else None
        else:
            tokens = line.split("#", 1)[0].split()
            if not tokens:
                continue
            if is_ip(tokens[0]):   # hosts line: "0.0.0.0 domain"
                tokens = tokens[1:]
            elif len(tokens) != 1:   # bare-domain line must hold exactly one name
                rejected += 1
                continue
            names = [normalize(t) for t in tokens]
            if not names or any(n is None for n in names):
                rejected += 1
                continue
            out.update(names)
            continue
        if name is None:
            rejected += 1
        else:
            out.add(name)
    return out, rejected


def parents(name):
    """Proper parent domains with at least two labels: a.b.c.com -> b.c.com, c.com."""
    labels = name.split(".")
    return (".".join(labels[i:]) for i in range(1, len(labels) - 1))


def collapse(names):
    """Drop names whose parent is also listed: a blocked zone already covers its subdomains."""
    return {n for n in names if not any(p in names for p in parents(n))}


def covered(name, blocked):
    return name in blocked or any(p in blocked for p in parents(name))


def read_names(path):
    if not path.exists():
        return set()
    names = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            n = normalize(line)
            if n is None:
                raise SystemExit(f"{path.name}: not a valid domain: {line!r}")
            names.add(n)
    return names


def fetch(url, cache):
    path = cache / hashlib.sha1(url.encode()).hexdigest() if cache else None
    if path and path.exists():
        return path.read_text(errors="replace")
    last = None
    for _ in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=120) as r:
                text = r.read().decode("utf-8", "replace")
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            return text
        except Exception as e:  # noqa: BLE001 - reported with the source name below
            last = e
    raise RuntimeError(f"{url}: {last}")


def load_sources(sources, cache):
    """Fetch and parse every source in parallel; returns {name: (domains, stats)} or raises on any failure."""
    def one(s):
        text = fetch(s["url"], cache)
        names, rejected = parse(text, s["format"])
        return s["name"], names, {
            "url": s["url"], "format": s["format"], "lines": text.count("\n"),
            "domains": len(names), "rejected": rejected, "tiers": s["tiers"],
        }

    out, failures = {}, []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(one, s): s for s in sources}
        for f in cf.as_completed(futs):
            s = futs[f]
            try:
                name, names, st = f.result()
            except Exception as e:  # noqa: BLE001
                failures.append(f"{s['name']}: fetch failed: {e}")
                continue
            if not names:
                failures.append(f"{s['name']}: parsed to zero domains")
            out[name] = (names, st)
    if failures:
        raise SystemExit("source problems:\n  " + "\n  ".join(sorted(failures)))
    return out


def build_tier(tier, loaded, extra_block, allow):
    union = set(extra_block)
    for names, st in loaded.values():
        if tier in st["tiers"]:
            union |= names
    allowed_hits = {n for n in union if covered(n, allow)}
    union -= allowed_hits
    # An allowed name below a still-blocked parent cannot be expressed in a flat list.
    stuck = sorted(a for a in allow if any(p in union for p in parents(a)) or a in union)
    final = collapse(union)
    return {"final": final, "union": len(union), "allow_removed": len(allowed_hits), "allow_stuck": stuck}


COSMETIC_RULE = re.compile(r"(~?[a-z0-9*.-]+(?:,~?[a-z0-9*.-]+)*)?#@?#(.+)")
NETWORK_RULE = re.compile(r"(?:@@)?[^\s#]+")


def balanced(selector):
    """True when the brackets, parentheses and quotes of a CSS selector are balanced."""
    stack, quote = [], None
    for ch in selector:
        if quote:
            quote = None if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch in "[(":
            stack.append(ch)
        elif ch in "])":
            if not stack or {"[": "]", "(": ")"}[stack.pop()] != ch:
                return False
    return not stack and quote is None


def check_rule(line):
    """None when a cosmetic.txt line is an acceptable uBlock/AdGuard rule, else the reason it is not."""
    if line != line.strip() or any(ord(c) < 32 for c in line):
        return "stray whitespace or control character"
    m = COSMETIC_RULE.fullmatch(line)
    if m:
        sel = m.group(2)
        if sel.startswith(("+js(", "^")) or "{" in sel or "}" in sel:
            return "scriptlets, HTML filters and style injection are not supported"
        return None if balanced(sel) else "unbalanced brackets, parentheses or quotes in the selector"
    return None if NETWORK_RULE.fullmatch(line) else "not a network or ## cosmetic rule"


def build_cosmetic(path, out, stamp):
    """Validate cosmetic.txt and publish it with a header; returns the number of rules."""
    kept, seen, errors = [], set(), []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith("!"):
            kept.append(line)
            continue
        problem = check_rule(line)
        if problem:
            errors.append(f"{path.name}:{n}: {problem}: {line!r}")
        elif line not in seen:
            seen.add(line)
            kept.append(line)
    if errors:
        raise SystemExit("invalid cosmetic rules:\n  " + "\n  ".join(errors))
    head = ["[Adblock Plus]", "! Title: blocklist cosmetic filters", f"! Updated: {stamp}",
            f"! Rules: {len(seen)}", "! Expires: 1 day"]
    (out / "cosmetic.txt").write_text("\n".join(head + kept) + "\n")
    return len(seen)


def header(title, tier, n, stamp, comment):
    return [f"{comment} Title: {title} ({tier})", f"{comment} Updated: {stamp}", f"{comment} Entries: {n}"]


def write_outputs(out, tier, names, stamp):
    suffix = "" if tier == "full" else "-lite"
    ordered = sorted(names, key=lambda d: d.split(".")[::-1])
    domains = header("blocklist", tier, len(ordered), stamp, "#") + ordered
    adblock = ["[Adblock Plus]"] + header("blocklist", tier, len(ordered), stamp, "!") + [f"||{d}^" for d in ordered]
    (out / f"domains{suffix}.txt").write_text("\n".join(domains) + "\n")
    (out / f"adblock{suffix}.txt").write_text("\n".join(adblock) + "\n")


def index_html(stats):
    rows = "".join(
        f"<tr><td>{html.escape(t)}</td><td>{v['entries']:,}</td>"
        f"<td><a href='domains{'' if t == 'full' else '-lite'}.txt'>domains</a></td>"
        f"<td><a href='adblock{'' if t == 'full' else '-lite'}.txt'>adblock</a></td></tr>"
        for t, v in stats["tiers"].items()
    )
    cosmetic = (f"<p><a href='cosmetic.txt'>cosmetic.txt</a> ({stats['cosmetic']['rules']:,} rules)</p>"
                if "cosmetic" in stats else "")
    return ("<!doctype html><meta charset=utf-8><title>blocklist</title><h1>blocklist</h1>"
            f"<p>Updated {html.escape(stats['updated'])}</p><table border=1 cellpadding=4>"
            f"<tr><th>tier</th><th>entries</th><th colspan=2>files</th></tr>{rows}</table>"
            f"{cosmetic}<p><a href='stats.json'>stats.json</a></p>")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--cache", type=Path, help="directory to cache downloads in (local development)")
    args = ap.parse_args(argv)

    cfg = tomllib.loads((ROOT / "sources.toml").read_text())
    sources = cfg["source"]
    loaded = load_sources(sources, args.cache)

    extra_block, allow = read_names(ROOT / "block.txt"), read_names(ROOT / "allow.txt")
    canary = read_names(ROOT / "canary.txt")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    args.out.mkdir(parents=True, exist_ok=True)

    stats = {"updated": stamp, "sources": {n: st for n, (_, st) in sorted(loaded.items())}, "tiers": {}}
    if (ROOT / "cosmetic.txt").exists():
        stats["cosmetic"] = {"rules": build_cosmetic(ROOT / "cosmetic.txt", args.out, stamp)}
    problems = []
    for tier in ("full", "lite"):
        t = build_tier(tier, loaded, extra_block, allow)
        final = t["final"]
        hits = sorted(c for c in canary if covered(c, final))
        if hits:
            problems.append(f"{tier}: canary domains are blocked: {', '.join(hits)}")
        write_outputs(args.out, tier, final, stamp)
        stats["tiers"][tier] = {"entries": len(final), "union": t["union"], "allow_removed": t["allow_removed"],
                                "allow_stuck": t["allow_stuck"]}
    (args.out / "stats.json").write_text(json.dumps(stats, indent=1) + "\n")
    (args.out / "index.html").write_text(index_html(stats))

    for tier, v in stats["tiers"].items():
        print(f"{tier}: {v['entries']:,} entries (union {v['union']:,}, allow removed {v['allow_removed']})")
        if v["allow_stuck"]:
            print(f"  warning: allowed but a blocked parent remains (needs an allow rule in the DNS server): "
                  f"{', '.join(v['allow_stuck'])}")
    if "cosmetic" in stats:
        print(f"cosmetic: {stats['cosmetic']['rules']} rules")
    if problems:
        raise SystemExit("not publishing:\n  " + "\n  ".join(problems))


if __name__ == "__main__":
    sys.exit(main())
