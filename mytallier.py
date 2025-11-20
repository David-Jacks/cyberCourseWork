#!/usr/bin/env python3
"""Tallier: fetch ballots after election closed, compute tally and print results.

This script expects the server to expose GET /ballots which returns
{"ballots": [{"voter_id":..., "choice":...}, ...]}
"""

import requests
from collections import Counter

BASE_URL = "http://localhost:5000"


def fetch_ballots():
    url = f"{BASE_URL}/ballots"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    return data.get("ballots", [])


def tally_and_print():
    ballots = fetch_ballots()
    if not ballots:
        print("no ballots found")
        return

    choices = [b.get("choice") for b in ballots]
    counts = Counter(choices)

    print("Election results:")
    for choice, count in counts.most_common():
        print(f"  {choice}: {count}")

    # Optionally, print full voter list who voted
    print("\nDetailed ballots:")
    for b in ballots:
        print(f"  {b.get('voter_id')}: {b.get('choice')}")


def tally_main():
    print("\nLogged in as Tallier.\n")
    try:
        tally_and_print()
    except requests.HTTPError as he:
        print("HTTP error:", he.response.status_code, he.response.text)
    except Exception as e:
        print("error:", e)
