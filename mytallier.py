#!/usr/bin/env python3
"""Tallier: fetch ballots after election closed, compute tally and print results.

This script expects the server to expose GET /ballots which returns
{"ballots": [{"voter_id":..., "choice":...}, ...]}
"""
BASE_URL = "http://localhost:5000"

import requests
from collections import Counter
import os
import json
try:
    from secure_utils import decrypt_ballot_with_both
except Exception:
    decrypt_ballot_with_both = None


def _maybe_load_keys_env():
    env_path = os.path.join(os.path.dirname(__file__), "keys", "keys.env")
    if not os.path.exists(env_path):
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=env_path)
        return
    except Exception:
        pass
    try:
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k.strip(), v)
    except Exception:
        pass


_maybe_load_keys_env()



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

   
    # For Shamir-based decryption we require Admin, Registrar and Tallier
    # private keys locally (3-of-3). This enforces that all three parties
    # must cooperate to decrypt ballots.
    admin_priv = os.environ.get("ADMIN_ENC_PRIV_KEY") or os.environ.get("ADMIN_PRIV_KEY") or os.environ.get("ADMIN_SIGN_PRIV_KEY")
    reg_priv = os.environ.get("REGISTRAR_ENC_PRIV_KEY") or os.environ.get("REGISTRAR_PRIV_KEY") or os.environ.get("REGISTRAR_SIGN_PRIV_KEY")
    tall_priv = os.environ.get("TALLIER_ENC_PRIV_KEY") or os.environ.get("TALLIER_PRIV_KEY") or os.environ.get("TALLIER_SIGN_PRIV_KEY")

    decrypted_choices = []
    # Require at least two private keys to decrypt (Shamir threshold=2).
    provided = [p for p in (admin_priv, reg_priv, tall_priv) if p]
    if len(provided) >= 2:
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

    # Determine winner (most common choice) but do NOT reveal counts
    # or any mapping to voters. If there is a tie we list tied options.
    counts = Counter([c for c in decrypted_choices if c is not None])
    if not counts:
        print("no valid votes decrypted")
        return

    most = counts.most_common()
    top_count = most[0][1]
    winners = [choice for choice, cnt in most if cnt == top_count]

    if len(winners) == 1:
        print("Election winner:", winners[0])
    else:
        print("Election winners (tie):", ", ".join(winners))


def tally_main():
    print("\nLogged in as Tallier.\n")
    try:
        tally_and_print()
    except requests.HTTPError as he:
        print("HTTP error:", he.response.status_code, he.response.text)
    except Exception as e:
        print("error:", e)
