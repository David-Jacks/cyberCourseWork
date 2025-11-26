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
import base64


def _maybe_load_keys_env():
    # Load canonical `keys.env` as specified in system design.
    env_dir = os.path.join(os.path.dirname(__file__), "keys")
    env_path = os.path.join(env_dir, "keys.env")
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

   
    # For this design we expect ballots to be encrypted with the ELECTION
    # public key. The election private key must be reconstructed via
    # Shamir secret sharing from trustee shares (admin+tallier). The
    # environment variables `ADMIN_SHARE` and `TALLIER_SHARE` are expected
    # to contain share spec strings in the form `x:BASE64` (or path to a
    # file containing that string). Two shares (threshold=2) are required.
    admin_share_spec = os.environ.get("ADMIN_SHARE")
    tallier_share_spec = os.environ.get("TALLIER_SHARE")

    if not admin_share_spec or not tallier_share_spec:
        print("ADMIN_SHARE and TALLIER_SHARE environment variables are required to reconstruct election private key.")
        return

    def _load_share(spec: str):
        # spec may be 'x:BASE64' or a path to a file with that content
        try:
            if os.path.exists(spec):
                with open(spec, "r") as f:
                    spec = f.read().strip()
            x_str, b64 = spec.split(":", 1)
            x = int(x_str)
            share_bytes = base64.b64decode(b64)
            return (x, share_bytes)
        except Exception:
            return None

    s_admin = _load_share(admin_share_spec)
    s_tall = _load_share(tallier_share_spec)
    if not s_admin or not s_tall:
        print("Failed to parse share specs. Expected 'x:BASE64' or path to file containing it.")
        return

    try:
        from secure_utils import combine_private_key_shares, decrypt_ballot_with_election_priv
    except Exception:
        print("required secure_utils helpers not available")
        return

    # Reconstruct election private key PEM bytes
    try:
        pem = combine_private_key_shares([s_admin, s_tall])
    except Exception as e:
        print("failed to combine shares:", e)
        return

    # Write reconstructed PEM to a temporary file to use decryption helper
    import tempfile
    tf = tempfile.NamedTemporaryFile(delete=False)
    try:
        tf.write(pem)
        tf.flush()
        priv_path = tf.name
    finally:
        tf.close()

    decrypted_choices = []
    for b in ballots:
        enc = b.get("encrypted_ballot")
        if enc:
            try:
                pt = decrypt_ballot_with_election_priv(priv_path, enc)
                parsed = json.loads(pt.decode("utf-8"))
                decrypted_choices.append(parsed.get("choice"))
            except Exception as e:
                print("warning: failed to decrypt a ballot:", e)
        else:
            decrypted_choices.append(b.get("choice"))

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
