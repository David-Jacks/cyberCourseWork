import signal
import sys
import json
import threading
import os
import base64
from my_utils import hash_id, verify_ed25519, rsa_decrypt_from_b64, rsa_encrypt_to_b64, encrypt_for_registrar, _maybe_load_keys_env
from my_sss import split_private_key_shares
from Schnorr_ZKP import deserialize_proof, voter_verify_proof, voter_secret_key, voter_public_key, generate_group
from http.server import HTTPServer, BaseHTTPRequestHandler


_maybe_load_keys_env()

# Getting the needed shared public keys the server will need need to verify the identity if the users
REGISTRAR_SIGN_PUB = os.environ.get("REGISTRAR_SIGN_PUB_KEY")
ADMIN_SIGN_PUB = os.environ.get("ADMIN_SIGN_PUB_KEY")
TALLIER_SIGN_PUB = os.environ.get("TALLIER_SIGN_PUB_KEY")
ELECTION_PUB = os.environ.get("ELECTION_PUB_KEY")
REGISTRAR_ENC_PUB = os.environ.get("REGISTRAR_ENC_PUB_KEY")

# this is the servers own private key, that it uses to decrypt encrypted messages sent over the network
SERVER_PRIV = os.environ.get("SERVER_PRIV_KEY")

#this is the electionstate class to manage the election
class ElectionState:
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


# - voters: map voter_id -> name
# - options: list of up to 4 location strings
# - ballots: list of dicts {"voter_id":..., "choice":...}
# Access to these structures should be thread-safe; reuse a lock used by
# ElectionState for simplicity (we can use a separate lock if desired).
voters = {}
options = ["Paris", "Rome", "Bahamas", "Lisbon"]
ballots = []
storage_lock = threading.Lock()

# getting the list of valid students from the my_db.JSON file
student_db = set()
db_path = "my_db.JSON"
if os.path.exists(db_path):
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            j = json.load(f)

        students = j.get('students', [])
        if not isinstance(students, list):
            student_db = set()
        else:
            for entry in students:
                if not isinstance(entry, dict):
                    continue
                if entry.get('hashed_id'):
                    student_db.add(entry['hashed_id'])
                elif entry.get('id'):
                    raw = str(entry['id']).strip()
                    if raw:
                        student_db.add(hash_id(raw) if hash_id is not None else raw)
    except Exception:
        print("Student db not connected")
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

    #this hanles all get requests that comes to the server
    def do_GET(self):
        # Root greeting
        if self.path in ("/"):
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
                    vlist = []
                    for vid, val in voters.items():
                        if isinstance(val, dict):
                            vlist.append({"voter_hash": vid, "enc_name": val.get("enc_name")})
                        else:
                            vlist.append({"voter_hash": vid, "enc_name": val})
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
            #i want to divide the the keys among the admin and tallier, before election can be tallyed
            election_priv = os.environ.get("ELECTION_PRIV_KEY")
            if election_priv and os.path.exists(election_priv):
                try:
                    shares = split_private_key_shares(election_priv, n=3, k=2)
                    # Do not print raw share bytes (sensitive). Log indices only.
                    try:
                        idxs = [s[0] for s in shares]
                        print(f"Derived share indices: {idxs}", flush=True)
                    except Exception:
                        pass
                    # shares is [(1, bytes), (2, bytes),(3, bytes)]
                    a_spec = f"{shares[0][0]}:{base64.b64encode(shares[0][1]).decode('ascii')}"
                    t_spec = f"{shares[1][0]}:{base64.b64encode(shares[1][1]).decode('ascii')}"
                    # only set if not already provided
                    os.environ.setdefault("ADMIN_SHARE", a_spec)
                    os.environ.setdefault("TALLIER_SHARE", t_spec)
                    admin_share_spec = os.environ.get("ADMIN_SHARE")
                    tallier_share_spec = os.environ.get("TALLIER_SHARE")
                    if admin_share_spec and tallier_share_spec:
                        print("Derived ADMIN_SHARE and TALLIER_SHARE from ELECTION_PRIV_KEY.")
                    else:
                        print("error splitting election priv keys")
                except Exception as e:
                    print("Failed to split election private key into shares:", e)
            with storage_lock:
                send_json(self, {"ballots": ballots})
            return

        # Fallback: not found
        send_text(self, "404 Not Found\n", status=404)

    #handles all post requests that comes to the server
    def do_POST(self):
        # Registration endpoint: allows registration only when election is closed
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

            # Accept ecrupted messages
            enc_voter_hash = payload.get("enc_voter_hash")
            enc_name = payload.get("enc_name")
            h_hex = payload.get("h")

            # If client did not supply a Schnorr public key, the server
            # can generate a short secret and corresponding public key and
            # return the encrypted secret to the registrar caller.
            enc_secret = None

            if not enc_voter_hash and not enc_name:
                send_text(self, "missing voter identifier\n", status=400)
                return

            vhash = None
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
                

            # checking if the voter is a valid student by checking the student_db using the hashed id
            if student_db:
                if vhash not in student_db:
                    send_text(self, "student details not recognised\n", status=403)
                    return
                
                stored_name = enc_name

                # If Schnorr params are configured and no `h` provided,
                # generate a short secret and compute the public key `h`.
                # Diagnostic: show current environment and headers affecting Schnorr secret generation
                sch_group = None
                try:
                    if not h_hex:
                        p = os.environ.get("SCHNORR_P")
                        q = os.environ.get("SCHNORR_Q")
                        g = os.environ.get("SCHNORR_G")
                        # If SCHNORR params absent but we can encrypt to the registrar,
                        # generate a temporary group for testing so we can produce
                        # a short secret and return it to the registrar. In
                        # production, distribute stable group parameters to clients.
                        if not (p and q and g) and REGISTRAR_ENC_PUB:
                            try:
                                grp = generate_group(bit_length=256)
                            except Exception as e:
                                print("DBG: generate_group failed, falling back to small test group:", e, flush=True)
                                grp = {'p': 23, 'q': 11, 'g': 2}
                            p_i = int(grp['p']); q_i = int(grp['q']); g_i = int(grp['g'])
                        elif p and q and g and REGISTRAR_ENC_PUB:
                            p_i = int(p); q_i = int(q); g_i = int(g)
                        else:
                            p_i = q_i = g_i = None

                        if p_i and q_i and g_i:
                            x = voter_secret_key()
                            print(f"DBG: generated short secret x={x}", flush=True)
                            h_val = voter_public_key(x, p_i, g_i)
                            h_hex = hex(h_val)
                            try:
                                enc_secret = rsa_encrypt_to_b64(REGISTRAR_ENC_PUB, str(x).encode('utf-8'))
                                print("DBG: rsa_encrypt_to_b64 succeeded", flush=True)
                            except Exception as e:
                                print("DBG: rsa_encrypt_to_b64 failed:", e, flush=True)
                                try:
                                    enc_secret = encrypt_for_registrar(REGISTRAR_ENC_PUB, str(x).encode("utf-8"))
                                    print("DBG: encrypt_for_registrar succeeded", flush=True)
                                except Exception as e2:
                                    print("DBG: encrypt_for_registrar failed:", e2, flush=True)
                                    enc_secret = None
                            # publish public group params so registrar/client can use them
                            try:
                                sch_group = {"p": str(p_i), "q": str(q_i), "g": str(g_i)}
                            except Exception:
                                sch_group = None
                except Exception as e:
                    # If generation fails, continue without Schnorr support
                    print("DBG: schnorr generation exception:", e, flush=True)
                    h_hex = h_hex

                # prevent duplicate registrations
                with storage_lock:
                    if vhash in voters:
                        send_text(self, "voter already registered\n", status=409)
                        return
                    # store as dict with enc_name and optional schnorr public key
                    entry = {"enc_name": stored_name}
                    if h_hex:
                        entry["h"] = h_hex
                    voters[vhash] = entry
                # Return non-sensitive confirmation (we do not echo raw voter_id)
                # Include any optional values (encrypted secret for registrar,
                # and public Schnorr group params) so the registrar/client can
                # use them.
                resp_obj = {"res_mes": "Registration complete"}
                if enc_secret and signer == "registrar":
                    resp_obj["enc_secret"] = enc_secret
                if sch_group is not None:
                    resp_obj["sch_group"] = sch_group
                send_json(self, resp_obj, status=201)
                return
            else:
                send_text(self, "database error \n", status=503)
           


        # Options endpoint: allows voters to see the list of options to be voted from, options can be viewed befroe the election opens.
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

        # Submitting ballot endpoint: allowed only when election is open
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
            
            #client encrypted ballot and encrypted voters hash retrieval
            enc_ballot = payload.get("encrypted_ballot")
            enc_voter_hash = payload.get("enc_voter_hash")

            if enc_ballot:
                if not enc_voter_hash:
                    send_text(self, "missing enc_voter_hash for encrypted ballot\n", status=400)
                    return
                #server private key will be needed to decrypted the encrypted voters hash 
                if rsa_decrypt_from_b64 is None or not SERVER_PRIV:
                    send_text(self, "server decryption unavailable\n", status=500)
                    return
                try:
                    vhash = rsa_decrypt_from_b64(SERVER_PRIV, enc_voter_hash).decode("utf-8")
                except Exception:
                    send_text(self, "failed to decrypt voter identifier\n", status=400)
                    return

                #check if voter exists in the registered voters list
                with storage_lock:
                    if vhash not in voters:
                        send_text(self, "Student not registered, speak to the Registrar,\n", status=403)
                        return
                    # if Schnorr public key stored, require proof
                    stored = voters.get(vhash)
                    stored_h_hex = None
                    if isinstance(stored, dict):
                        stored_h_hex = stored.get("h")

                    if stored_h_hex:
                        pr = payload.get("proof")
                        if not pr:
                            send_text(self, "proof required\n", status=400)
                            return
                        try:
                            t, c, s, h_client = deserialize_proof(pr.get("t"), pr.get("c"), pr.get("s"), pr.get("h"))
                        except Exception:
                            send_text(self, "invalid proof format\n", status=400)
                            return
                        try:
                            stored_h_val = int(stored_h_hex, 16) if isinstance(stored_h_hex, str) else int(stored_h_hex)
                        except Exception:
                            send_text(self, "server stored key invalid\n", status=500)
                            return
                        # verify h in proof matches stored h
                        if h_client != stored_h_val:
                            send_text(self, "proof public key mismatch\n", status=403)
                            return
                        # load group params
                        try:
                            p = int(os.environ.get("SCHNORR_P"))
                            q = int(os.environ.get("SCHNORR_Q"))
                            g = int(os.environ.get("SCHNORR_G"))
                        except Exception:
                            send_text(self, "Schnorr group not configured\n", status=500)
                            return
                        ok = voter_verify_proof(stored_h_val, t, c, s, p, q, g, message=vhash.encode("utf-8"))
                        if not ok:
                            send_text(self, "invalid proof\n", status=403)
                            return
                    # prevent double-voting by hashed id
                    if any(b.get("voter_hash") == vhash for b in ballots):
                        send_text(self, "You already voted, you are allowed to vote once for fairness\n", status=409)
                        return

                    # Store encrypted ballot as-is (server never holds election private key)
                    ballots.append({"voter_hash": vhash, "encrypted_ballot": enc_ballot})

                send_text(self, "Ballot accepted\n", status=201)
                return
            else:
                send_text(self, "Ballot not found\n", status=403)


        # Open voting endpoint: allows admin to open election
        if self.path == "/election/open":
            # Verify admin signature if available.
            sig_b64 = self.headers.get("X-Signature")
            signer = self.headers.get("X-Signer")
        
            # making sure it is the admin that is openning the election and no one else
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
            else:
                send_text(self, "admin signature not found\n", status=403)
                return
            
            election.set("open")
            send_text(self, "voting opened\n", status=200)
            return

        # Close voting endpoint: allows admin to close election
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

        # I want to reply with a 404 status when the endpoint is not defined
        send_text(self, "404 Not Found\n", status=404)

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