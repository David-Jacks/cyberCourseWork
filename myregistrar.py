#!/usr/bin/env python3
"""
Registrar CLI: register voters and set options before the election opens.

This script talks to the server on localhost:5000 and provides simple
commands:
- add     : register a voter (allowed while election closed)
- list-voters                : fetch and print registered voters
- show-options               : fetch and print options

"""

import sys
import requests
import os
import base64
import json
from typing import Optional


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

# Optional cryptographic helpers. If `REGISTRAR_PRIV_KEY` points to a PEM
# private key, registration requests will be signed and include `X-Signature`.
try:
    from secure_utils import sign_ed25519
except Exception:
    sign_ed25519 = None

BASE_URL = "http://localhost:5000"


def add_voter(voter_id, name):
    url = f"{BASE_URL}/register"
    # Basic client-side validation to catch common mistakes early. The server
    # also enforces the regex, so this is just a convenience.
    import re, os
    id_re = os.environ.get("STUDENT_ID_REGEX")
    if id_re and not re.match(id_re, str(voter_id)):
        print("invalid voter_id format locally (matches STUDENT_ID_REGEX)")
        return

    # Hash the voter id and encrypt the name for transport/storage.
    try:
        from secure_utils import hash_id, encrypt_for_registrar
    except Exception:
        hash_id = None
        encrypt_for_registrar = None

    # Validate locally against regex if configured
    import re
    id_re = os.environ.get("STUDENT_ID_REGEX")
    if id_re and not re.match(id_re, str(voter_id)):
        print("invalid voter_id format locally (matches STUDENT_ID_REGEX)")
        return

    voter_hash = hash_id(voter_id) if hash_id is not None else voter_id

    # Encrypt the hashed voter id to the server so nothing raw is sent.
    try:
        from secure_utils import rsa_encrypt_to_b64
    except Exception:
        rsa_encrypt_to_b64 = None

    enc_voter_hash = None
    if rsa_encrypt_to_b64 is not None and os.environ.get("SERVER_PUB_KEY"):
        try:
            enc_voter_hash = rsa_encrypt_to_b64(os.environ.get("SERVER_PUB_KEY"), voter_hash.encode("utf-8"))
        except Exception:
            enc_voter_hash = None

    # Encrypt name for Registrar (so only Registrar can decrypt stored names)
    enc_name = None
    if encrypt_for_registrar is not None and os.environ.get("REGISTRAR_ENC_PUB_KEY"):
        try:
            enc_name = encrypt_for_registrar(os.environ.get("REGISTRAR_ENC_PUB_KEY"), name.encode("utf-8"))
        except Exception:
            enc_name = None

    payload = {}
    if enc_voter_hash:
        payload["enc_voter_hash"] = enc_voter_hash
    else:
        payload["voter_hash"] = voter_hash
    if enc_name:
        payload["enc_name"] = enc_name
    else:
        payload["name"] = name
    # If a Registrar private key is configured, sign the registration payload
    # and include the signature in headers. The server will verify it if it
    # has the corresponding public key.
    headers = {}
    # Prefer explicit signing key, fall back to legacy names
    keypath = os.environ.get("REGISTRAR_SIGN_PRIV_KEY") or os.environ.get("REGISTRAR_PRIV_KEY") or os.environ.get("REGISTRAR_ENC_PRIV_KEY")
    payload_bytes = json.dumps(payload).encode("utf-8")
    if keypath and sign_ed25519 is not None:
        try:
            sig = sign_ed25519(keypath, payload_bytes)
            headers["X-Signature"] = base64.b64encode(sig).decode("ascii")
            headers["X-Signer"] = "registrar"
        except Exception as e:
            print("warning: failed to sign registration payload:", e)

    resp = requests.post(url, json=payload, timeout=5, headers=headers)
    resp.raise_for_status()
    print("registered:", resp.json() if resp.content else resp.text)


def list_voters():
    url = f"{BASE_URL}/voters"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    print(resp.json())


def show_options():
    url = f"{BASE_URL}/options"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    print("these are the option to vote from: ", resp.json().get("options", []))


def usage_and_exit():
    print("Usage: myregistrar.py add <voter_id> <name> | set-options <opt1> [opt2].. | list-voters | show-options")
    sys.exit(2)


def reg_main():
    print("\nLogged in as Registrar.")
    print("1. Register a student voter")
    print("2. List registered voters")
    print("3. List available options to be voted on")
    print("4. exit")

    userInput = input("Please make a choice: ").strip() #handling issues where user inputs spaces before or after the input

    if userInput == "1":
        voter_id = input("Enter voter ID: ")
        name = input("Enter voter name: ")
        try:
            add_voter(voter_id, name)
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "2":
        try:
            list_voters()
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "3":
        try:
            show_options()
        except requests.HTTPError as he:
            print("HTTP error:", he.response.status_code, he.response.text)
        except Exception as e:
            print("error:", e)
    elif userInput == "4":
        print("Logged out Goodbye!")
        return
    else:
        print("Invalid choice. Please try again.")
        return  
