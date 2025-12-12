import os
import json
import sys
import requests
import re
from my_utils import DEFAULT_HOST, DEFAULT_TIMEOUT, encrypt_ballot_with_election_pub, rsa_encrypt_to_b64, hash_id, _maybe_load_keys_env
from Schnorr_ZKP import voter_generate_proof, serialize_proof
from myregistrar import add_voter
from mytallier import tally_main


def get(url: str, timeout: float = DEFAULT_TIMEOUT):
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


def check_state(timeout: float = DEFAULT_TIMEOUT):
    """Return the current election state as a string ('open' or 'closed'), or None on error."""
    try:
        res = get(DEFAULT_HOST + "/election/state", timeout=timeout)
        try:
            parsed = json.loads(res["body"])
            return parsed.get("state")
        except Exception:
            return "open" if "open" in res["body"] else ("closed" if "closed" in res["body"] else None)
    except Exception:
        return None


def get_options(timeout: float = DEFAULT_TIMEOUT):
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


def submit_ballot(voter_id: str, choice: str, timeout: float = DEFAULT_TIMEOUT, voter_secret: str = None):
    """Submit a ballot. Returns (status_code, text) or raises requests.RequestException."""
    # Require `ELECTION_PUB_KEY` and `SERVER_PUB_KEY` to be configured
    # per design: ballots are encrypted with the election public key and
    # hashed voter identifiers are encrypted to the server public key.
    election_pub = os.environ.get("ELECTION_PUB_KEY")
    server_pub = os.environ.get("SERVER_PUB_KEY")

    if not election_pub or not server_pub or hash_id is None:
        print("Missing ELECTION_PUB_KEY, SERVER_PUB_KEY or hashing support")
        return

    voter_hash = hash_id(voter_id)
    # Encrypt hashed id to server
    enc_voter_hash = rsa_encrypt_to_b64(server_pub, voter_hash.encode("utf-8"))
    # Encrypt ballot to election public key
    ballot = {"voter_hash": voter_hash, "choice": choice}
    plaintext = json.dumps(ballot).encode("utf-8")
    enc_ballot = encrypt_ballot_with_election_pub(election_pub, plaintext)
    payload = {"enc_voter_hash": enc_voter_hash, "encrypted_ballot": enc_ballot}
    # Schnorr proof (optional): include proof if Schnorr group configured
    # Ensure any keys/env written by the registrar (keys/keys.env) are loaded
    try:
        _maybe_load_keys_env()
    except Exception:
        pass

    try:
        p = os.environ.get("SCHNORR_P")
        q = os.environ.get("SCHNORR_Q")
        g = os.environ.get("SCHNORR_G")
        if p and q and g:
            p_i = int(p)
            q_i = int(q)
            g_i = int(g)
            # obtain secret (either passed in or prompt)
            if voter_secret is None:
                try:
                    voter_secret = input("Enter your 3-digit secret: ").strip()
                except Exception:
                    voter_secret = None
            if voter_secret is not None:
                x = int(voter_secret)
                proof = voter_generate_proof(x, p_i, q_i, g_i, message=voter_hash.encode("utf-8"))
                t_hex, c_hex, s_hex, h_hex = serialize_proof(proof)
                payload["proof"] = {"t": t_hex, "c": c_hex, "s": s_hex, "h": h_hex}
    except Exception:
        pass
    resp = requests.post(DEFAULT_HOST + "/vote", json=payload, timeout=timeout)
    return resp.status_code, resp.text


def _cast_vote(timeout: float = DEFAULT_TIMEOUT, regex_ref = None):
    print("\nLogged in as Student.\n")

    # Check election state first
    state = check_state(timeout=timeout)

    if state is None:
        print("Could not determine election state.")
        return
    if state != "open":
        print(f"Election is not open for voting. Current state: {state} please contact admin.")
        print("\nLogged Out.")
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
    # ensure a usable regex is available
    if regex_ref is None:
        regex_ref = re.compile(r"^[0-9]{8}$")
    if not voter_id or regex_ref.match(voter_id) is None:
        print("Voter ID required or invalid format.")
        return

    choice_in = input("Enter choice (number): ").strip()
    if not choice_in:
        print("Choice required")
        return

    try:
        idx = int(choice_in)
    except ValueError:
        print("Invalid choice number")
        return

    if 1 <= idx <= len(opts):
        choice = opts[idx - 1]
    else:
        print("Invalid choice number")
        return

    try:
        # Prompt for the short secret token so the client always asks the voter
        try:
            voter_secret = input("Enter your 3-digit secret : ").strip()
        except Exception:
            voter_secret = None
        if voter_secret == "":
            voter_secret = None

        status_code, text = submit_ballot(voter_id, choice, timeout=timeout, voter_secret=voter_secret)
        print(f"{status_code}")
        print(text)
    except requests.RequestException as e:
        print(f"Request error: {e}", file=sys.stderr)
        return


def voting_client(timeout: float = DEFAULT_TIMEOUT):
    """Interactive voting client for students."""

    id_regex = re.compile(r"^[0-9]{8}$")

    print("\nStudent Menu\n")
    print("1. Register")
    print("2. Cast Vote")
    print("3. See Election Results")
    print("Enter B to go back")
    stud_choice = input("Please make a choice: ").strip()
    while stud_choice.upper() != "B":
        if stud_choice == "1":
            voter_id = input("Enter voter ID: ")
            name = input("Enter voter name: ")
            if id_regex.match(voter_id) is None:
                print("Invalid voter ID format.")
                return
            try:
                #calling the add_voter function from myregistrar to register a new student
                add_voter(voter_id, name)
            except requests.HTTPError as he:
                print("HTTP error:", he.response.status_code, he.response.text)
            except Exception as e:
                print("error:", e)
        elif stud_choice == "2":
            _cast_vote(timeout=timeout)
        elif stud_choice == "3":
            tally_main()
        else:
            print("Invalid choice. Please try again.")

        print("\nStudent Menu")
        print("1. Register")
        print("2. Cast Vote")
        print("3. See Election Results")
        print("Enter B to go back")
        stud_choice = input("Please make a choice: ").strip()

