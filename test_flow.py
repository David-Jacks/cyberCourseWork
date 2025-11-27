#!/usr/bin/env python3
"""End-to-end test harness (in-process) for the voting clients.

This script does NOT start an HTTP server. Instead it monkeypatches
`requests.get` and `requests.post` to route calls to local handler
functions implementing a minimal server state required by the clients.

Flow performed:
  - generate keys (election, server, registrar)
  - set environment variables expected by clients
  - register a student via `myregistrar.add_voter`
  - open election via `myadmin.open_election`
  - submit a ballot via `myclient.submit_ballot`
  - close election via `myadmin.close_election`
  - run `mytallier.tally_and_print` and print winner

This exercises encryption, hashing and Shamir share split/combine.
"""

import os
import sys
import json
import base64
import tempfile
from types import SimpleNamespace

import requests

import secure_utils
import myregistrar
import myadmin
import myclient
import mytallier


# --- Helper: generate RSA key pair and return (priv_pem, pub_pem) ---
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def gen_rsa_keypair(bits=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


# --- Minimal in-memory server state ---
SERVER_STATE = {
    "state": "closed",
    "options": ["Alice", "Bob", "Carol"],
    # voters: map hashed_id -> name
    "voters": {},
    # ballots: list of dicts with keys 'enc_voter_hash' and 'encrypted_ballot'
    "ballots": [],
}


# We'll keep generated private keys (PEM bytes) here so handlers can decrypt.
KEYS = {}


class MockResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data
        self.headers = {"Content-Type": "application/json"}
        self.content = json.dumps(data).encode("utf-8") if data is not None else b""
        self.text = json.dumps(data) if data is not None else ""

    def json(self):
        return self._data

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            err = requests.HTTPError(f"{self.status_code} HTTP error")
            err.response = self
            raise err


def mock_get(url, headers=None, timeout=None):
    path = url.split("//", 1)[-1].split('/', 1)[-1]
    if path.startswith("election/state"):
        return MockResponse(200, {"state": SERVER_STATE["state"]})
    if path.startswith("options"):
        return MockResponse(200, {"options": SERVER_STATE["options"]})
    if path.startswith("voters"):
        return MockResponse(200, {"voters": list(SERVER_STATE["voters"].keys())})
    if path.startswith("ballots"):
        return MockResponse(200, {"ballots": SERVER_STATE["ballots"]})
    return MockResponse(404, {"error": "not found"})


def mock_post(url, json=None, timeout=None, headers=None):
    path = url.split("//", 1)[-1].split('/', 1)[-1]
    if path.startswith("election/open"):
        SERVER_STATE["state"] = "open"
        return MockResponse(200, {"result": "opened"})
    if path.startswith("election/close"):
        SERVER_STATE["state"] = "closed"
        return MockResponse(200, {"result": "closed"})
    if path.startswith("register"):
        # expect enc_voter_hash or voter_hash
        payload = json or {}
        enc = payload.get("enc_voter_hash")
        vh = None
        if enc:
            # decrypt with server private key
            try:
                priv_path = KEYS.get("server_priv_path")
                vh = secure_utils.rsa_decrypt_from_b64(priv_path, enc).decode("utf-8")
            except Exception as e:
                return MockResponse(400, {"error": f"decrypt failed: {e}"})
        else:
            vh = payload.get("voter_hash")

        # check that hashed id is in allowed list (we assume allowed student hashed ids)
        allowed = KEYS.get("allowed_hashes", set())
        if vh not in allowed:
            return MockResponse(400, {"error": "student id not in database"})
        if vh in SERVER_STATE["voters"]:
            return MockResponse(400, {"error": "already registered"})

        # decrypt name if present
        name = None
        if "enc_name" in payload and KEYS.get("registrar_priv_path"):
            try:
                name = secure_utils.rsa_decrypt_from_b64(KEYS.get("registrar_priv_path"), payload.get("enc_name")).decode("utf-8")
            except Exception:
                name = None
        else:
            name = payload.get("name")

        SERVER_STATE["voters"][vh] = name or ""
        return MockResponse(200, {"result": "registered"})

    if path.startswith("vote"):
        payload = json or {}
        # Basic checks: election must be open
        if SERVER_STATE["state"] != "open":
            return MockResponse(400, {"error": "election not open"})
        # Accept enc_voter_hash and encrypted_ballot
        enc_vh = payload.get("enc_voter_hash")
        enc_ballot = payload.get("encrypted_ballot")
        if not enc_vh or not enc_ballot:
            return MockResponse(400, {"error": "missing fields"})
        # decrypt voter hash
        try:
            vh = secure_utils.rsa_decrypt_from_b64(KEYS.get("server_priv_path"), enc_vh).decode("utf-8")
        except Exception as e:
            return MockResponse(400, {"error": f"decrypt failed: {e}"})
        # check registration
        if vh not in SERVER_STATE["voters"]:
            return MockResponse(400, {"error": "not registered"})
        # check double-vote: prevent same vh voting twice
        for b in SERVER_STATE["ballots"]:
            # ballots store enc_voter_hash so compare decrypted
            try:
                existing_vh = secure_utils.rsa_decrypt_from_b64(KEYS.get("server_priv_path"), b.get("enc_voter_hash")).decode("utf-8")
                if existing_vh == vh:
                    return MockResponse(400, {"error": "duplicate vote"})
            except Exception:
                pass

        SERVER_STATE["ballots"].append({"enc_voter_hash": enc_vh, "encrypted_ballot": enc_ballot})
        return MockResponse(200, {"result": "vote accepted"})

    return MockResponse(404, {"error": "not found"})


def setup_env_and_keys(student_ids=None):
    # generate keys
    server_priv, server_pub = gen_rsa_keypair()
    election_priv, election_pub = gen_rsa_keypair()
    registrar_priv, registrar_pub = gen_rsa_keypair()

    # write election private key to a temp file (tallier expects a path)
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(election_priv)
    tf.flush()
    tf.close()
    os.environ["ELECTION_PRIV_KEY"] = tf.name
    # put public PEMs as raw PEM strings in env vars (clients accept PEM string)
    os.environ["ELECTION_PUB_KEY"] = election_pub.decode("utf-8")
    os.environ["SERVER_PUB_KEY"] = server_pub.decode("utf-8")
    os.environ["REGISTRAR_ENC_PUB_KEY"] = registrar_pub.decode("utf-8")

    # save server and registrar private key paths for decryption in mock handlers
    spf = tempfile.NamedTemporaryFile(delete=False)
    spf.write(server_priv)
    spf.flush(); spf.close()
    KEYS["server_priv_path"] = spf.name

    rpf = tempfile.NamedTemporaryFile(delete=False)
    rpf.write(registrar_priv)
    rpf.flush(); rpf.close()
    KEYS["registrar_priv_path"] = rpf.name

    # allowed student hashes in server DB (accept multiple student ids)
    if student_ids is None:
        student_ids = ["s12345"]
    allowed = {secure_utils.hash_id(sid) for sid in student_ids}
    KEYS["allowed_hashes"] = allowed


def run_flow():
    # patch requests
    requests.get = mock_get
    requests.post = mock_post

    # Define several students to simulate an interactive session
    students = [
        ("a001", "Alice A"),
        ("b002", "Bob B"),
        ("s12345", "Sam S"),
        ("d004", "Dana D"),
    ]

    # Prepare env and keys allowing these students
    setup_env_and_keys(student_ids=[s[0] for s in students])

    # Registrar registering students (summary line)
    ids_str = ", ".join([s[0] for s in students])
    names_str = ", ".join([s[1] for s in students])
    print(f"Registrar Registering students {names_str}, with ids {ids_str}")

    # Register each student (simulated interactive actions)
    for sid, name in students:
        print(f"  Registrar: registering {name} (id={sid})")
        myregistrar.add_voter(sid, name)

    # Print registered students (hashed id -> name) for transparency
    print("\nRegistered students (hashed_id -> name):")
    for hid, name in SERVER_STATE["voters"].items():
        print(f"  {hid} -> {name}")

    print("\nAdmin opening election")
    myadmin.open_election()

    print("\nStudents voting")
    opts = myclient.get_options()
    # Each student votes for a different option in sequence (wrap if needed)
    for idx, (sid, name) in enumerate(students):
        choice = opts[idx % len(opts)] if opts else "Alice"
        print(f"  Student {name} (id={sid}) voting for {choice}")
        status, text = myclient.submit_ballot(sid, choice)
        print(f"    submit result: {status} {text}")

    # Show stored ballots (encrypted) for transparency
    print("\nStored ballots (encrypted):")
    for i, b in enumerate(SERVER_STATE["ballots"], start=1):
        print(f"  Ballot #{i}:")
        print(f"    enc_voter_hash: {b.get('enc_voter_hash')}")
        print(f"    encrypted_ballot: {json.dumps(b.get('encrypted_ballot'))}")

    # Attempt to decrypt ballots using the election private key (for test transparency)
    try:
        priv_path = os.environ.get("ELECTION_PRIV_KEY")
        print("\nDecrypted ballots (voter_hash -> choice):")
        for i, b in enumerate(SERVER_STATE["ballots"], start=1):
            enc_ballot = b.get("encrypted_ballot")
            try:
                pt = secure_utils.decrypt_ballot_with_election_priv(priv_path, enc_ballot)
                parsed = json.loads(pt.decode("utf-8"))
                print(f"  Ballot #{i}: {parsed.get('voter_hash')} -> {parsed.get('choice')}")
            except Exception as e:
                print(f"  Ballot #{i}: failed to decrypt: {e}")
    except Exception as e:
        print("Could not decrypt ballots for transparency:", e)

    print("--- Closing election ---")
    myadmin.close_election()

    print("--- Tallying ---")
    mytallier.tally_and_print()


if __name__ == "__main__":
    run_flow()
