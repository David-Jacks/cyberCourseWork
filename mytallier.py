#!/usr/bin/env python3
"""Tallier: fetch ballots after election closed, compute tally and print results.

This script expects the server to expose GET /ballots which returns
{"ballots": [{"voter_id":..., "choice":...}, ...]}
"""

import requests
from collections import Counter
import os
import json
try:
    from secure_utils import decrypt_ballot_with_both
except Exception:
    decrypt_ballot_with_both = None

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

    # Decryption requires both Registrar and Tallier private keys in this
    # simple example. This enforces the "two-entity" requirement: both
    # parties must participate to reveal plaintext ballots.
    # For Shamir-based decryption we require Admin, Registrar and Tallier
    # private keys locally (3-of-3). This enforces that all three parties
    # must cooperate to decrypt ballots.
    admin_priv = os.environ.get("ADMIN_PRIV_KEY")
    reg_priv = os.environ.get("REGISTRAR_PRIV_KEY")
    tall_priv = os.environ.get("TALLIER_PRIV_KEY")

    decrypted_choices = []
    if admin_priv and reg_priv and tall_priv:
        try:
            from secure_utils import decrypt_ballot_shamir_all
        except Exception:
            decrypt_ballot_shamir_all = None

        if decrypt_ballot_shamir_all is None:
            print("Shamir decryption helper not available (install cryptography?).")
            return

        for b in ballots:
            enc = b.get("encrypted")
            if enc:
                try:
                    pt = decrypt_ballot_shamir_all(admin_priv, reg_priv, tall_priv, enc)
                    parsed = json.loads(pt.decode("utf-8"))
                    decrypted_choices.append(parsed.get("choice"))
                except Exception as e:
                    print("warning: failed to decrypt a ballot:", e)
            else:
                # legacy/plain ballots
                decrypted_choices.append(b.get("choice"))
    else:
        print("Admin, Registrar and Tallier private keys are required to decrypt ballots.")
        print("Provide ADMIN_PRIV_KEY, REGISTRAR_PRIV_KEY and TALLIER_PRIV_KEY environment variables to tally.")
        return

    counts = Counter([c for c in decrypted_choices if c is not None])

    print("Election results:")
    for choice, count in counts.most_common():
        print(f"  {choice}: {count}")

    # Optionally, print full voter list who voted (hashed ids only)
    print("\nDetailed ballots:")
    for b in ballots:
        print(f"  {b.get('voter_hash')}: {b.get('encrypted') and '[encrypted]' or b.get('choice')}")


def tally_main():
    print("\nLogged in as Tallier.\n")
    try:
        tally_and_print()
    except requests.HTTPError as he:
        print("HTTP error:", he.response.status_code, he.response.text)
    except Exception as e:
        print("error:", e)
