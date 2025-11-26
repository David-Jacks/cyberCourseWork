#!/usr/bin/env python3
"""Simplified HTTP server with a thread-safe election state.

This file provides a minimal, easy-to-read implementation that keeps the
original behavior:

- GET /             -> plain text greeting
- GET /election/state -> JSON {"state": "open"|"closed"}
- POST /election/open  -> set state to "open" (text response)
- POST /election/close -> set state to "closed" (text response)
- POST /election/state -> set state via JSON payload {"state": "open"}

The original code used a subclass hook to inject endpoints; here we implement
the handler directly for clarity.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import signal
import sys
import json
import threading
import os
import base64


def _maybe_load_keys_env():
    # Load the required `keys.env` (single canonical file per design)
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
    # Fallback simple parser (KEY=VALUE lines)
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

# Runtime configuration: student ID regex and admin secret
# - `STUDENT_ID_REGEX` can be set in environment to enforce allowed ID pattern
#   and make guessing attacks harder. Default is one example format.
STUDENT_ID_REGEX = os.environ.get("STUDENT_ID_REGEX", r"^[A-Z]{2}[0-9]{6}$")
import re
_ID_PATTERN = re.compile(STUDENT_ID_REGEX)

# Optional admin pre-shared secret (if set on the server, admin clients must
# provide the same secret via the `X-Admin-Secret` header). This is separate
# from the admin signing key and provides an additional authentication factor
# for critical operations (open/close).
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")

# Optional secure helpers. If `cryptography` and `secure_utils.py` are
# available they will be used; otherwise the server falls back to the
# original behaviour (no verification/encryption).
try:
    from secure_utils import hash_id, verify_ed25519, rsa_decrypt_from_b64, decrypt_ballot_with_election_priv, encrypt_for_registrar
except Exception:
    hash_id = None
    verify_ed25519 = None
    rsa_decrypt_from_b64 = None
    decrypt_ballot_with_election_priv = None
    encrypt_for_registrar = None

# Public key paths (signing). Server/private key path for decrypting hashed IDs.
REGISTRAR_SIGN_PUB = os.environ.get("REGISTRAR_SIGN_PUB_KEY")
ADMIN_SIGN_PUB = os.environ.get("ADMIN_SIGN_PUB_KEY")
TALLIER_SIGN_PUB = os.environ.get("TALLIER_SIGN_PUB_KEY")
SERVER_PRIV = os.environ.get("SERVER_PRIV_KEY")
ELECTION_PUB = os.environ.get("ELECTION_PUB_KEY")
REGISTRAR_ENC_PUB = os.environ.get("REGISTRAR_ENC_PUB_KEY")


class ElectionState:
    """Thread-safe storage for the election state.

    Only two values are allowed: "open" and "closed". Access is protected by
    a Lock so the state can be safely read/written from multiple threads.
    """

    def __init__(self, initial="closed"):
        self._state = initial
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            return self._state

    def set(self, value):
        if value not in ("open", "closed"):
            raise ValueError("invalid state")
        with self._lock:
            self._state = value


# Single global election state used by the handler
election = ElectionState()


# In-memory storage for voters, options and ballots
# - `voters`: map voter_id -> name
# - `options`: list of up to 4 location strings
# - `ballots`: list of dicts {"voter_id":..., "choice":...}
# Access to these structures should be thread-safe; reuse a lock used by
# ElectionState for simplicity (we can use a separate lock if desired).
voters = {}
options = ["Paris", "Rome", "Bahamas", "Lisbon"]
ballots = []
storage_lock = threading.Lock()

# Optional student database (list of allowed student identifiers). If
# `STUDENT_DB_FILE` env var is set it should point to a file with one
# student identifier per line; the server will store the hashed values
# (using `hash_id`) for membership checks.
student_db = set()
db_file = os.environ.get("STUDENT_DB_FILE")
if db_file and os.path.exists(db_file):
    try:
        with open(db_file, "r") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if hash_id is not None:
                    student_db.add(hash_id(s))
                else:
                    student_db.add(s)
    except Exception:
        student_db = set()


def send_json(handler, obj, status=200):
    """Send a JSON response using the provided request handler."""
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_text(handler, text, status=200):
    """Send a plain-text response using the provided request handler."""
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class reqHandler(BaseHTTPRequestHandler):
    """HTTP request handler with explicit api endpoints."""

    def do_GET(self):
        # Root greeting
        if self.path in ("/", "/index"):
            send_text(self, "Voting Server is running on port 5000\n", status=200)
            return

        # Return current election state as JSON
        if self.path == "/election/state":
            send_json(self, {"state": election.get()})
            return

        # Return list of registered voters
        if self.path == "/voters":
            # Return as list of {"voter_id": id, "name": name}
            # Return hashed voter identifiers and encrypted names. The
            # server never exposes raw voter_id values in production.
            with storage_lock:
                vlist = [{"voter_hash": vid, "enc_name": name} for vid, name in voters.items()]
            send_json(self, {"voters": vlist})
            return

        # Return configured options
        if self.path == "/options":
            with storage_lock:
                send_json(self, {"options": options})
            return

        # Return ballots only after the election has been closed
        if self.path == "/ballots":
            if election.get() != "closed":
                send_text(self, "ballots available only after election is closed\n", status=403)
                return
            # Return encrypted ballots. If a TALLIER_PUB key is configured the
            # server expects the request to be authenticated by the tallier.
            sig_b64 = self.headers.get("X-Signature")
            signer = self.headers.get("X-Signer")
            if TALLIER_SIGN_PUB and signer == "tallier":
                if not sig_b64 or verify_ed25519 is None:
                    send_text(self, "tallier signature required\n", status=403)
                    return
                try:
                    sig = base64.b64decode(sig_b64)
                    # Verify over empty body for this simple example
                    if not verify_ed25519(TALLIER_SIGN_PUB, b"", sig):
                        send_text(self, "invalid tallier signature\n", status=403)
                        return
                except Exception:
                    send_text(self, "invalid signature format\n", status=403)
                    return

            with storage_lock:
                send_json(self, {"ballots": ballots})
            return

        # Fallback: not found
        send_text(self, "404 Not Found\n", status=404)

    def do_POST(self):
        # Registration endpoint: add a voter when election is closed (before opening)
        if self.path == "/register":
            if election.get() != "closed":
                send_text(self, "registration allowed only while election is closed\n", status=403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length) if length else b""
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                send_text(self, "invalid JSON\n", status=400)
                return

            # Verify registrar signature if present and a public key is
            # configured. The signature should be over the raw request body.
            sig_b64 = self.headers.get("X-Signature")
            signer = self.headers.get("X-Signer")
            if REGISTRAR_SIGN_PUB and signer == "registrar":
                if not sig_b64 or verify_ed25519 is None:
                    send_text(self, "registrar signature required\n", status=403)
                    return
                try:
                    sig = base64.b64decode(sig_b64)
                    if not verify_ed25519(REGISTRAR_SIGN_PUB, raw, sig):
                        send_text(self, "invalid registrar signature\n", status=403)
                        return
                except Exception:
                    send_text(self, "invalid signature format\n", status=403)
                    return

            # Accept either an encrypted hashed voter handle (`enc_voter_hash`),
            # a pre-hashed `voter_hash`, or a raw `voter_id`. Registrar clients
            # should send `enc_voter_hash` (encrypted to server) and `enc_name`
            # when available so no raw identifiers are transmitted.
            enc_voter_hash = payload.get("enc_voter_hash")
            voter_hash = payload.get("voter_hash")
            raw_voter_id = payload.get("voter_id")
            enc_name = payload.get("enc_name")
            plain_name = payload.get("name")

            if not enc_voter_hash and not voter_hash and not raw_voter_id:
                send_text(self, "missing voter identifier\n", status=400)
                return

            vhash = None
            if enc_voter_hash:
                # Decrypt encrypted hashed id using server private key
                if rsa_decrypt_from_b64 is None or not SERVER_PRIV:
                    send_text(self, "server decryption unavailable\n", status=500)
                    return
                try:
                    plain = rsa_decrypt_from_b64(SERVER_PRIV, enc_voter_hash)
                    vhash = plain.decode("utf-8")
                except Exception:
                    send_text(self, "failed to decrypt voter identifier\n", status=400)
                    return
            elif voter_hash:
                vhash = voter_hash
            else:
                # Validate and hash raw voter id
                if not _ID_PATTERN.match(str(raw_voter_id)):
                    send_text(self, "invalid voter_id format\n", status=400)
                    return
                vhash = hash_id(raw_voter_id) if hash_id is not None else raw_voter_id

            # If a student_db is configured, require that the hashed id is listed
            if student_db and vhash not in student_db:
                send_text(self, "student details not recognised\n", status=403)
                return

            # Determine how the name is provided: prefer `enc_name` (already
            # encrypted by the Registrar), else accept plaintext `name` and
            # encrypt it for the Registrar if configured.
            if enc_name:
                stored_name = enc_name
            elif plain_name:
                if encrypt_for_registrar is not None and REGISTRAR_ENC_PUB:
                    try:
                        stored_name = encrypt_for_registrar(REGISTRAR_ENC_PUB, plain_name.encode("utf-8"))
                    except Exception:
                        stored_name = plain_name
                else:
                    stored_name = plain_name
            else:
                stored_name = ""

            with storage_lock:
                if vhash in voters:
                    send_text(self, "voter already registered\n", status=409)
                    return
                voters[vhash] = stored_name

            # Return non-sensitive confirmation (we do not echo raw voter_id)
            send_json(self, {"voter_hash": vhash, "name_encrypted": bool(REGISTRAR_ENC_PUB)}, status=201)
            return

        # Configure options (allowed only while election is closed)
        if self.path == "/options":
            if election.get() != "closed":
                send_text(self, "options may only be set while election is closed\n", status=403)
                return

            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length) if length else b""
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                send_text(self, "invalid JSON\n", status=400)
                return

            opts = payload.get("options")
            if not isinstance(opts, list) or not opts or len(opts) > 4:
                send_text(self, "options must be a list of 1-4 values\n", status=400)
                return

            with storage_lock:
                options.clear()
                options.extend([str(o) for o in opts])

            send_json(self, {"options": options}, status=201)
            return

        # Submit a ballot: allowed only when election is open
        if self.path == "/vote":
            if election.get() != "open":
                send_text(self, "election is not open for voting\n", status=403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length) if length else b""
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                send_text(self, "invalid JSON\n", status=400)
                return

            # Support encrypted ballots: client should send `enc_voter_hash`
            # (RSA-OAEP encrypted hashed id to server) and `encrypted_ballot`
            # (hybrid AES-GCM + RSA-OAEP ciphertext encrypted to election pub).
            enc_ballot = payload.get("encrypted_ballot")
            enc_voter_hash = payload.get("enc_voter_hash")

            if enc_ballot:
                if not enc_voter_hash:
                    send_text(self, "missing enc_voter_hash for encrypted ballot\n", status=400)
                    return
                if rsa_decrypt_from_b64 is None or not SERVER_PRIV:
                    send_text(self, "server decryption unavailable\n", status=500)
                    return
                try:
                    vhash = rsa_decrypt_from_b64(SERVER_PRIV, enc_voter_hash).decode("utf-8")
                except Exception:
                    send_text(self, "failed to decrypt voter identifier\n", status=400)
                    return

                with storage_lock:
                    if vhash not in voters:
                        send_text(self, "Student not registered, speak to the Registrar,\n", status=403)
                        return
                    # prevent double-voting by hashed id
                    if any(b.get("voter_hash") == vhash for b in ballots):
                        send_text(self, "You already voted, you are allowed to vote once for fairness\n", status=409)
                        return

                    # Store encrypted ballot as-is (server never holds election private key)
                    ballots.append({"voter_hash": vhash, "encrypted_ballot": enc_ballot})

                send_text(self, "Ballot accepted\n", status=201)
                return

            # Fallback: older/plain behaviour -- accept clear ballots and
            # still use hashed voter lookup if possible.
            voter_id = payload.get("voter_id")
            choice = payload.get("choice")
            if not voter_id or choice is None:
                send_text(self, "missing voter_id or choice\n", status=400)
                return

            # Validate ID format on votes as well
            if not _ID_PATTERN.match(str(voter_id)):
                send_text(self, "invalid voter_id format\n", status=400)
                return

            vhash = hash_id(voter_id) if hash_id is not None else voter_id

            with storage_lock:
                if vhash not in voters:
                    send_text(self, "Student not registered, speak to the Registrar,\n", status=403)
                    return
                if any(b.get("voter_hash") == vhash for b in ballots):
                    send_text(self, "You already voted, you are allowed to vote once for fairness\n", status=409)
                    return
                if choice not in options:
                    send_text(self, "invalid choice\n", status=400)
                    return

                # store as encrypted=False legacy ballot (server still stores
                # voter_hash to avoid raw ids in ballot list)
                ballots.append({"voter_hash": vhash, "choice": choice})

            send_text(self, "Ballot accepted\n", status=201)
            return

        # Open voting
        if self.path == "/election/open":
            # Verify admin signature if available.
            sig_b64 = self.headers.get("X-Signature")
            signer = self.headers.get("X-Signer")
            # Optional admin secret check (additional factor). If ADMIN_SECRET
            # is configured on the server then the client must also send this
            # secret in the `X-Admin-Secret` header.
            if ADMIN_SECRET:
                provided = self.headers.get("X-Admin-Secret")
                if not provided or provided != ADMIN_SECRET:
                    send_text(self, "admin secret required\n", status=403)
                    return

            if ADMIN_SIGN_PUB and signer == "admin":
                if not sig_b64 or verify_ed25519 is None:
                    send_text(self, "admin signature required\n", status=403)
                    return
                try:
                    sig = base64.b64decode(sig_b64)
                    if not verify_ed25519(ADMIN_SIGN_PUB, b"", sig):
                        send_text(self, "invalid admin signature\n", status=403)
                        return
                except Exception:
                    send_text(self, "invalid signature format\n", status=403)
                    return

            election.set("open")
            send_text(self, "voting opened\n", status=200)
            return

        # Close voting
        if self.path == "/election/close":
            sig_b64 = self.headers.get("X-Signature")
            signer = self.headers.get("X-Signer")
            if ADMIN_SIGN_PUB and signer == "admin":
                if not sig_b64 or verify_ed25519 is None:
                    send_text(self, "admin signature required\n", status=403)
                    return
                try:
                    sig = base64.b64decode(sig_b64)
                    if not verify_ed25519(ADMIN_SIGN_PUB, b"", sig):
                        send_text(self, "invalid admin signature\n", status=403)
                        return
                except Exception:
                    send_text(self, "invalid signature format\n", status=403)
                    return

            election.set("closed")
            send_text(self, "voting closed\n", status=200)
            return

        # Unknown POST endpoint
        send_text(self, "404 Not Found\n", status=404)

    def log_message(self, format, *args):
        # Route logs to stdout in a compact format (same as before).
        sys.stdout.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), format % args))


def run(host="127.0.0.1", port=5000):
    """Start the HTTP server and install a SIGINT handler for clean shutdown."""

    server = HTTPServer((host, port), reqHandler)
    print(f"Serving HTTP on http://{host}:{port} (Press CTRL+C to quit)")

    def handle_sigint(signum, frame):
        print("\nShutting down server")
        server.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    server.serve_forever()


if __name__ == "__main__":
    run()