**Security Design and Implementation Guide**

This document explains where and how to implement common security measures in the repository (files: `myserver.py`, `myclient.py`, `myregistrar.py`, `myadmin.py`, `mytallier.py`). It does not change existing code — instead it maps design decisions, the specific endpoints and functions where security should be enforced, and provides concrete example snippets and operational guidance.

**Goals**
- Protect voter identities and ballot integrity.
- Prevent tampering with registrations and ballots.
- Provide auditability without compromising voter anonymity.

**High-level choices**
- Transport: use TLS (HTTPS) in production — run behind a TLS-terminating reverse proxy (nginx, Caddy) or enable `ssl` in Python `http.server` if needed for testing.
- Authentication & Authorization: use asymmetric keys for signing messages exchanged between clients (Registrar, Admin) and the server; optionally use API keys + TLS for connections.
- Integrity: use digital signatures on critical messages (registrations, ballot submissions, admin commands).
- Privacy / minimal storage: store hashed identifiers where possible and store non-linkable ballot records.

**Where to apply each technique (file & endpoint mapping)**

- Hashing (one-way) — purpose: protect stored identifiers and produce non-reversible voter handles.
  - Implement in `myserver.py`:
    - On `POST /register`: instead of storing raw `voter_id`, store a salted cryptographic hash (e.g. HMAC or PBKDF2/Argon2) of `voter_id`. Keep a server-side secret salt/key in a secure location (not in repo). Use `hmac` or `hashlib.pbkdf2_hmac`.
    - In `POST /vote`: accept the `voter_id` in the request but compare via the hashed form (hash the provided `voter_id` with the same salt/key and compare against stored hashed ids).
    - Benefit: if storage is leaked, raw IDs are not revealed.

- Digital Signatures — purpose: ensure authenticity and non-repudiation of actions.
  - Who signs: `myregistrar` signs registrations; `myadmin` signs open/close commands; `myclient` (student) signs ballots optionally (or uses a one-time token signed by Registrar).
  - Implement in both client-side modules (`myregistrar.py`, `myadmin.py`, optionally `myclient.py`) and server-side verification in `myserver.py`:
    - Keypairs: each role (Registrar, Admin, Tallier) gets an asymmetric keypair (Ed25519 or RSA). Public keys are deployed to the server's trusted-keys store (or a simple JSON file loaded at server start).
    - On `POST /register`: Registrar signs the registration JSON (voter_id, name, timestamp). The server verifies the Registrar signature before accepting registration.
    - On `POST /election/open` and `/election/close`: Admin's client signs the request; server verifies signature before transitioning state.
    - On `POST /vote`: either the student's ballot is signed with a per-voter key (if keys are distributed) or the ballot includes a registrar-issued signed voting token (a short-lived token proving the student is eligible). The server verifies the token or signature and records the ballot.

- Asymmetric Encryption — purpose: protect confidentiality of messages where needed (e.g., storing ballots encrypted until tally time or encrypting ballots for the tallier so only tallier can decrypt).
  - Implement in `myserver.py` and `mytallier.py`:
    - Option A (server-side encrypted ballots): encrypt ballot contents with the Tallier's public key before persisting; the tallier later decrypts with his private key to tally. This keeps server storage confidential if the server is compromised.
    - Option B (client-side encryption): client encrypts the ballot with tallier's public key and sends ciphertext to server. Server stores ciphertext; tallier fetches ciphertext and decrypts for tallying.
    - Use modern algorithms (e.g. RSA-OAEP or ECIES or hybrid encryption using ECDH + symmetric cipher like AES-GCM). Prefer libs: `cryptography` (high-level primitives) or `pyca/cryptography`.

**Detailed mapping: endpoints and recommended changes**

- `myserver.py`:
  - `POST /register`:
    - Verify Registrar signature on payload.
    - Hash `voter_id` before storing: use HMAC-SHA256 with a server secret key, or use Argon2/PBKDF2 with salt for stronger resistance.
    - Store only hashed id and optionally a registration signature/receipt to present to voter.

  - `GET /voters`:
    - Return only hashed voter IDs or an internal mapping; avoid returning raw IDs in production.

  - `POST /options`:
    - Verify Registrar signature (if Registrar should be the only one to set options).

  - `POST /election/open` and `/election/close`:
    - Require Admin signature; verify signature before calling `election.set(...)`.

  - `POST /vote`:
    - Accept either: (a) a registrar-signed voting token proving the voter is allowed to vote, or (b) client's signature using voter's private key.
    - Use hashed voter lookup: compute HMAC(hash_key, voter_id) and ensure the hashed id matches a registered hashed id.
    - Optionally encrypt ballot choice using Tallier public key before storing so only Tallier can decrypt.
    - Ensure double-voting prevention is performed on hashed id (not raw id).

  - `GET /ballots`:
    - Return decrypted ballots only to an authenticated Tallier (verify Tallier signature on request). Alternatively return ciphertexts and let Tallier decrypt locally.

- `myclient.py`:
  - Student flow (`sys_stater`) may send either clear ballots (if server protects them) or a registrar-signed token + ballot signed by voter. Implement helper to attach digital signature to POST `/vote` payload.

- `myregistrar.py`:
  - On `add_voter` (client side): sign registration payload with Registrar private key before sending. The server must verify signature.
  - Optionally, Registrar can issue a short-lived signed voting token that the student will use to submit a ballot later.

- `myadmin.py`:
  - `open_election` / `close_election`: sign admin commands with Admin private key. The server must verify signature before applying state changes.

- `mytallier.py`:
  - For tallying: fetch ciphertext ballots and decrypt with Tallier private key, then tally.
  - Verify signatures on ballots/tokens as needed.

**Key management**
- Keys should never be checked into the repository.
- For local development, keep keys in `~/.voting/keys/` with restrictive permissions, or use environment variables that hold encrypted keys.
- The server must have trusted public keys for Admin, Registrar, Tallier. Example: `trusted_keys.json` with role -> public key mapping. Load it at server start.

**Example Python snippets**

- HMAC hashing of voter_id (server-side):

```py
import hmac
import hashlib

HMAC_KEY = b"replace-with-secure-random-key"

def hash_voter_id(voter_id: str) -> str:
    return hmac.new(HMAC_KEY, voter_id.encode('utf-8'), hashlib.sha256).hexdigest()
```

- Signing with Ed25519 (client-side Registrar / Admin):

```py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# load private key (PEM) from secure storage
priv = Ed25519PrivateKey.from_private_bytes(b"...32 bytes...")
sig = priv.sign(b"message-bytes")

# server verifies using public key
pub = Ed25519PublicKey.from_public_bytes(b"...32 bytes...")
pub.verify(sig, b"message-bytes")
```

- Hybrid encryption of ballot (encrypt with Tallier public key):

Use `cryptography` high-level primitives (examples omitted here). For production, use an agreed hybrid scheme (ECDH + AES-GCM) or RSA-OAEP.

**Message formats and headers**
- Signed requests should include headers like:
  - `X-Signature: base64(signature-bytes)`
  - `X-Signer: registrar` (role identifier)
  - `Date: RFC1123-timestamp` (include in signed payload to avoid replay)

The server verifies signature over canonical payload: e.g. JSON body + Date header.

**Replay protection & freshness**
- Include timestamps and short expiry (e.g., `ts` field and/or `Date` header) in signed payloads. Server should reject messages older than an allowed window (e.g., 2 minutes) and keep a small cache of recent nonces/timestamps to prevent simple replays.

**Privacy considerations & tallying**
- To preserve anonymity: do not store raw voter_id next to their ballot. Use hashed ids for uniqueness checks, and if possible strip or irreversibly separate identifying information before storing ballots.
- If ballots are encrypted for the Tallier, the server should store ciphertexts and never persist decryption keys.

**Operational checklist for implementing these measures**
- Add a new helper module `crypto_utils.py` containing:
  - key loading helpers
  - sign/verify helpers
  - hash helpers
  - encrypt/decrypt helpers
- Add server-side verification calls in `myserver.py` endpoints described above.
- Update `myregistrar.py` and `myadmin.py` to sign outgoing critical requests.
- Decide whether students will have keys; otherwise implement registrar-signed tokens.
- Add `trusted_keys.json` (example only) in deployment; keep private keys out of repo.

**Recommended libraries**
- `cryptography` (pyca/cryptography) — modern and maintained.
- `argon2-cffi` or `bcrypt` for password-style hashing if needed.

**Example workflow (Registrar issues token + student votes)**
1. Registrar registers voter: sends signed `{"voter_id": ..., "name": ..., "ts": ...}`. Server verifies signature and stores `hmac(voter_id)`.
2. Registrar issues short-lived voting token: `token = sign({"voter_hash": hmac(voter_id), "expiry": ...})` and gives token to student (out-of-band or printed).
3. Student submits ballot: POST `/vote` with `{"token": <token>, "choice": ...}`. Server verifies token signature and expiry, then records (optionally encrypting the choice with Tallier public key) and marks `voter_hash` as having voted.

**Testing notes**
- For development, you can generate ephemeral keys and store them in `tests/keys/` but ensure `.gitignore` excludes private keys in other environments.
- Write unit tests for sign/verify, encryption/decryption and for replay windows.

**Next steps (I can implement if you want)**
- Add `crypto_utils.py` and wire basic signing/verification for `POST /election/open` and `/register`.
- Add sample key generation scripts and a small README for key management.

If you want, I can now implement the helper module and instrument `myserver.py` + `myadmin.py` + `myregistrar.py` to demonstrate the flow. Tell me whether you prefer Registrar-signed tokens for students or distributing keys to students.
