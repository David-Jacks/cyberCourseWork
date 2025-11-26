# Simple Electronic Voting (Student Summer Location)

This system is a voting system that allows students in an institution to vote for a location for summer vacation the institution was planning. The involved locations were Bahamas, Paris, South Africa, and Rome. Students were allowed to vote free and fair and were assured of security and fairness in the voting as we didn’t want a situation where someone would cheat. This is a report to evaluate my system and vividly analyse the design, methodologies and security measures used for my system

**This README explains**:
- The system structure and purpose of each script
- The security problems the system aims to solve and the measures used
- Known limitations and attack surface
- How to run the system locally and an included end-to-end test script

**Components (purpose & interaction)**
- `myserver.py` — HTTP server exposing REST endpoints, holds in-memory state
	(voters, options, ballots). It validates IDs, enforces election state and
	performs signature and secret checks for admin/registrar/tallier actions.
- `myregistrar.py` — Registrar client: registers voters and sets options
	(talks to server's `/register` and `/options`). Uses signing key when
	available.
- `myadmin.py` — Admin client: opens/closes election. Signs admin commands
	and can include a shared `ADMIN_SECRET` header for an additional factor.
- `myclient.py` — Student client: interactive voter interface; encrypts
	ballots for multi-party decryption when public keys are configured.
- `mytallier.py` — Tallier client: fetches ballots after close and prints
	winner(s) without revealing counts or voter mappings.
- `secure_utils.py` — Cryptographic helpers: hashing, signing, RSA and
	Shamir secret sharing helpers. Implements AES-GCM encryption with a
	Shamir-split AES key (threshold 2-of-3).
- `generate_keys.sh` — Script to create signing (Ed25519) and encryption
	(RSA) keys and write `keys/keys.env` with env var names for components.

**Security goals & measures**
- Prevent simple ID guessing: the server enforces a `STUDENT_ID_REGEX`
	(configurable via env) to limit allowed ID formats.
- Hide raw IDs: server stores deterministic hashes of voter IDs using a
	server-side `HASH_PEPPER` (env). This prevents trivial precomputation of
	hashes by attackers.
- Confidential ballots in transit: ballots are encrypted client-side with
	AES-GCM. The AES key is split using Shamir secret sharing and shares are
	encrypted with RSA public keys for the Admin / Registrar / Tallier.
- Threshold decryption (two-party): Shamir threshold is 2-of-3 — at least
	two parties must cooperate to reconstruct AES key and decrypt ballots.
- Registrar confidentiality: voter names are encrypted specifically for the
	Registrar (only the Registrar's private key can decrypt names).
- Minimal disclosure at tally: the tallier prints only the winning option
	name(s), not counts or who voted for what.
- Admin controls: admin operations require a signature (admin signing key)
	and optionally an `ADMIN_SECRET` (second factor) configured on the server.

**Threats / Open attack surfaces**
- Key leakage: if private keys or `HASH_PEPPER`/`ADMIN_SECRET` are exposed,
	confidentiality and integrity are lost. Protect keys with file
	permissions or a secrets manager.
- Replay/Impersonation: this demo does not implement per-session auth for
	students. A determined attacker could impersonate a student if they know
	the allowed ID format. The `STUDENT_ID_REGEX` is only a weak mitigation.
- Server compromise: as the server holds hashed IDs and encrypted ballots,
	a compromised server could exfiltrate encrypted blobs. Without private
	keys attackers cannot decrypt ballots, but other attacks remain possible.
- Denial-of-service: no rate-limiting or hardened request validation — an
	attacker could flood the server.
- Insider threats: Admin/Registrar/Tallier roles have power; ensure
	separation of roles and secure key storage (offline or HSM where
	appropriate).

**How keys & env vars are used**
- `generate_keys.sh` creates keys and writes `keys/keys.env`. It produces
	explicit signing vs encryption variables:
	- `*_SIGN_PRIV_KEY` / `*_SIGN_PUB_KEY` — Ed25519 signing keys
	- `*_ENC_PRIV_KEY`  / `*_ENC_PUB_KEY`  — RSA encryption keys
	Backwards-compatible names (like `REGISTRAR_PRIV_KEY`) are also written.
- The Python scripts auto-load `keys/keys.env` (via `python-dotenv` if
	available, otherwise a simple parser). You can also set env vars directly
	in your environment.

**Quick setup (recommended)**
1. Install dependencies:
```bash
python3 -m pip install --user requests cryptography python-dotenv
```
2. Generate keys (writes `keys/keys.env`):
```bash
./generate_keys.sh
```
3. Start the server (in one terminal):
```bash
export ADMIN_SECRET="my-admin-secret"    # optional extra factor
export HASH_PEPPER="some-secret-pepper" # protect hashed IDs
python3 myserver.py
```

4. In another terminal run registrar/admin/clients as needed. Example
	 (no signatures required if signing pubkeys are not present):
```bash
# Registrar: register a voter (interactive)
python3 myregistrar.py
# Admin: open/close
python3 myadmin.py
# Student client
python3 myclient.py
# Tallier (after close)
python3 mytallier.py
```

**End-to-end test script**
An automated end-to-end test script is provided at `tests/e2e_test.sh`. It
performs a minimal flow: generate keys, start the server in the background,
register a voter, set options, open the election, submit a vote, close the
election, and run the tallier to print the winner. The script is self-
contained and sets an `ADMIN_SECRET` to allow admin operations without
interactive signing.

Run the test (from repository root):
```bash
chmod +x tests/e2e_test.sh
tests/e2e_test.sh
```

Notes about the test script:
- The script sets temporary env vars before starting the server so its
	built-in dotenv loader does not force signature checks. This keeps the
	test simple and deterministic for demo purposes.
- For stronger testing include cryptographic signatures in the HTTP
	requests and run the test in an environment with `cryptography` installed.

**Developer notes & recommended next steps**
- Add a startup key-type validation in `myserver.py` to fail fast when a
	configured key is the wrong type (RSA vs Ed25519).
- Consider integrating a secret manager (AWS KMS/HashiCorp Vault) for
	private key and pepper storage.
- If you want a Zero-Knowledge Proof (ZKP) approach (e.g., prove a vote
	is correctly formed without revealing its content) we can add a scoped
	primitive — note that ZKPs add complexity and often require external
	libraries.

**Support & testing**
- If you want, I can:
	- Run the `tests/e2e_test.sh` script here and show the output.
	- Add startup key-type validation and clearer error messages.
	- Draft a simple deployment recipe using systemd or Docker.

---

This README focuses on clarity and minimalism: security features are kept
explicit and documented so you can extend or harden them for production
use. If you'd like I will now add key-type validation and run the
end-to-end test for you.


