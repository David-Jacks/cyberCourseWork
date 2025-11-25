import json
import sys
import requests
import myregistrar
import myadmin
import mytallier
import os
from secure_utils import hash_id, encrypt_ballot_for_two

#!/usr/bin/env python3
"""
Simple HTTP GET client for http://localhost:5000
Sends a GET request to the given path (default "/") and prints status, headers, and body.
"""


DEFAULT_HOST = "http://localhost:5000"


def get(url: str, timeout: float = 5.0):
    headers = {"Accept": "*/*", "User-Agent": "myclient/1.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        print(f"Connection error: {e}")
        return None

    status = f"{resp.status_code}"
    headers = dict(resp.headers)
    body_text = resp.text

    ctype = headers.get("Content-Type", "")
    if "application/json" in ctype and resp.content:
        try:
            parsed = resp.json()
            body = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            body = body_text
    else:
        body = body_text

    return {"status": status, "headers": headers, "body": body}


def check_state(timeout: float = 5.0):
    """Return the current election state as a string ('open' or 'closed'), or None on error."""
    try:
        res = get(DEFAULT_HOST + "/election/state", timeout=timeout)
        # res['body'] is pretty-printed JSON when available
        try:
            parsed = json.loads(res["body"])
            return parsed.get("state")
        except Exception:
            return "open" if "open" in res["body"] else ("closed" if "closed" in res["body"] else None)
    except Exception:
        return None


def get_options(timeout: float = 5.0):
    """Fetch configured options; return list or None on error."""
    try:
        res = get(DEFAULT_HOST + "/options", timeout=timeout)
        try:
            parsed = json.loads(res["body"])
            return parsed.get("options", [])
        except Exception:
            return []
    except Exception:
        return None


def submit_ballot(voter_id: str, choice: str, timeout: float = 5.0):
    """Submit a ballot. Returns (status_code, text) or raises requests.RequestException."""
    # Prefer encrypting ballots client-side when Registrar and Tallier public
    # keys are configured. The encrypted payload requires both Registrar and
    # Tallier private keys to decrypt (see secure_utils).
    reg_pub = os.environ.get("REGISTRAR_PUB_KEY")
    tall_pub = os.environ.get("TALLIER_PUB_KEY")

    # require all three public keys (admin, registrar, tallier) for Shamir scheme
    admin_pub = os.environ.get("ADMIN_PUB_KEY")
    if admin_pub and reg_pub and tall_pub and hash_id is not None:
        try:
            from secure_utils import encrypt_ballot_shamir
        except Exception:
            encrypt_ballot_shamir = None

        if encrypt_ballot_shamir is not None:
            voter_hash = hash_id(voter_id)
            ballot = {"voter_hash": voter_hash, "choice": choice}
            plaintext = json.dumps(ballot).encode("utf-8")
            enc = encrypt_ballot_shamir(admin_pub, reg_pub, tall_pub, plaintext)
            payload = {"encrypted": enc, "voter_hash": voter_hash}
            resp = requests.post(DEFAULT_HOST + "/vote", json=payload, timeout=timeout)
            return resp.status_code, resp.text

    # Fallback: send unhashed voter_id (existing behaviour) - servers may
    # expect this for deployments that haven't configured keys.
    resp = requests.post(DEFAULT_HOST + "/vote", json={"voter_id": voter_id, "choice": choice}, timeout=timeout)
    return resp.status_code, resp.text


def sys_stater(timeout: float = 5.0):
    """Interactive flow: check state, list options, prompt voter, and submit ballot."""
    # Check election state first
    state = check_state(timeout=timeout)
    if state is None:
        print("Could not determine election state.")
        return
    if state != "open":
        print(f"Election is not open for voting. Current state: {state} please contact admin.")
        return

    opts = get_options(timeout=timeout)
    if opts is None:
        print("Could not retrieve voting options.")
        return
    if not opts:
        print("No options configured for this election.")
        return

    print("Available choices:")
    for i, o in enumerate(opts, start=1):
        print(f"  {i}. {o}")

    voter_id = input("Voter ID: ").strip()
    if not voter_id:
        print("Voter ID required")
        return

    choice_in = input("Enter choice (number): ").strip()
    if not choice_in:
        print("Choice required")
        return

    # resolve choice
    
    idx = int(choice_in)
    if 1 <= idx <= len(opts):
        choice = opts[idx - 1]
    else:
        print("Invalid choice number")
        return
  

    try:
        status_code, text = submit_ballot(voter_id, choice, timeout=timeout)
        print(f"{status_code}")
        print(text)
    except requests.RequestException as e:
        print(f"Request error: {e}", file=sys.stderr)
        return


def main():
    timeout = 5.0
    # check if the client is connected to the server
    if get(DEFAULT_HOST, timeout=timeout) is None:
        print("The Voting server is not running @", DEFAULT_HOST)
        sys.exit(2)
    print("Electronic voting system connected to -", DEFAULT_HOST)
    print("Please Login")
    print("1. Student")
    print("2. Admin")
    print("3. Tallier")
    print("4. Registrar")
    print("Enter X to close")
    userinput = input("Please make a choice: ").strip()  
    while userinput != "X":
        
        if userinput == "1":
            print("\nLogged in as Student.")
            sys_stater(timeout=timeout)
        elif userinput == "2":
            myadmin.admin_main()
        elif userinput == "3":
            mytallier.tally_main()
        elif userinput == "4":
            myregistrar.reg_main()
        else:
            print("Invalid choice. Please try again.")

        print("\n-----------------\n")
        print("Please Login")
        print("1. Student")
        print("2. Admin")
        print("3. Tallier")
        print("4. Registrar")
        print("Enter X to close")
        userinput = input("Please make a choice: ").strip()  


if __name__ == "__main__":
    main()