#!/usr/bin/env python3
"""Picks a domain that is in a blocklist feed right now.

Indicators age out of live feeds (IOC decay), so a scenario that needs "a domain the app's blocklist
holds" must not name one for good. The harness pipes the feed the app itself downloads (adblock format,
`||domain^`) into this script and uses the domain it prints.

    curl -fsSL <feed url> | python3 live-indicator.py      -> prints one domain; exit 1 when none fits
"""
import re
import sys

# A plain rule for a whole domain: no options after `^`, ASCII labels, a letter-only top-level label
# (so no IP addresses), and no punycode, which a shell command and a report line would spell differently.
_RULE = re.compile(r"^\|\|((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\^$")


def pick(feed: str) -> str | None:
    """The first plain whole-domain rule of [feed], in file order; None when there is none."""
    for line in feed.splitlines():
        match = _RULE.match(line.strip())
        if match and "xn--" not in match.group(1):
            return match.group(1)
    return None


if __name__ == "__main__":
    domain = pick(sys.stdin.read())
    if domain is None:
        sys.exit(1)
    print(domain)
