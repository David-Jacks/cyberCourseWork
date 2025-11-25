**Security — simple summary of what was added and how to use it**

This project now contains a simple, demonstrative security layer. The goal
was to: prevent linking votes to students, prevent double-voting, encrypt
votes in transit and at rest, and require two separate parties to decrypt
votes. Below is a short, easy-to-read explanation of what I changed and how
to use it.

What I added (files)
- `secure_utils.py` — new helper module that provides:
  - `hash_id(voter_id)` — non-reversible SHA-256 hash used as a voter handle.
  - Ed25519/RSA sign/verify helpers.
  - `encrypt_ballot_for_two(...)` / `decrypt_ballot_with_both(...)` — a
    hybrid encryption scheme where the AES key is split into two shares and
    each share is encrypted to a different RSA public key. Both private keys
    are required to decrypt.
- `requirements.txt` — lists `cryptography` dependency.

Files I updated and what they now do
- `myregistrar.py` (client): when `REGISTRAR_PRIV_KEY` is set the script
  signs registration requests and sends the signature in `X-Signature`.

- `myadmin.py` (client): when `ADMIN_PRIV_KEY` is set the script signs
  open/close commands (also `X-Signature`). The server verifies these.

- `myclient.py` (student client): when both `REGISTRAR_PUB_KEY` and
  `TALLIER_PUB_KEY` environment variables are set, the client encrypts the
  ballot locally using the two-share scheme and sends only the encrypted
  payload plus `voter_hash`. This keeps choices confidential from the
  server and other roles.

- `myserver.py` (server):
  - Verifies Registrar/Admin signatures when the corresponding public key
    env vars are configured (`REGISTRAR_PUB_KEY`, `ADMIN_PUB_KEY`).
  - On `POST /register` stores only `voter_hash` (not raw id) and stores
    the voter's name encrypted for the Registrar if the Registrar public key
    is configured. Raw IDs are not kept on the server.
  - On `POST /vote` accepts encrypted ballots (and stores ciphertext plus
    `voter_hash`) or accepts legacy plain ballots. Double-vote prevention
    is done using `voter_hash` only.
  - On `GET /ballots` returns only encrypted ballots. If `TALLIER_PUB_KEY`
    is configured the server requires a tallier signature to fetch them.

- `mytallier.py` (tallier): fetches encrypted ballots and decrypts them
  only when both `REGISTRAR_PRIV_KEY` and `TALLIER_PRIV_KEY` are available
  locally. This enforces the "two-entity" decryption requirement.

How these changes meet your requirements (plain language)
- We do not store raw voter IDs next to ballots. The server stores a
  non-reversible `voter_hash` so votes cannot easily be traced back to a
  student's raw ID.
- Double-voting is prevented by checking `voter_hash` — even though the
  server doesn't know raw IDs it can still detect repeated hashes.
- Votes are encrypted before being sent (when both public keys are set).
  The client encrypts ballots using AES-GCM and a two-share scheme so both
  Registrar and Tallier private keys are required to decrypt.
- The Registrar holds the ability to recover registered names (names are
  encrypted for the Registrar). Admin/Tallier/server see only encrypted
  names and `voter_hash` values.
- The Tallier can decrypt and tally votes without learning which student
  made each vote (they see decrypted choices and `voter_hash`, not raw IDs).

Quick setup and test (local development)
1. Install dependency:
```bash
python3 -m pip install -r requirements.txt
```

2. Generate test keys (example):
```bash
# Registrar RSA (encryption share)
openssl genpkey -algorithm RSA -out registrar_enc_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in registrar_enc_priv.pem -pubout -out registrar_enc_pub.pem

# Tallier RSA (encryption share)
openssl genpkey -algorithm RSA -out tallier_enc_priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in tallier_enc_priv.pem -pubout -out tallier_enc_pub.pem

# Registrar signing key (Ed25519)
openssl genpkey -algorithm ed25519 -out registrar_sign_priv.pem
openssl pkey -in registrar_sign_priv.pem -pubout -out registrar_sign_pub.pem

# Admin signing key (Ed25519)
openssl genpkey -algorithm ed25519 -out admin_sign_priv.pem
openssl pkey -in admin_sign_priv.pem -pubout -out admin_sign_pub.pem
```

3. Export environment variables (example):
```bash
export REGISTRAR_PRIV_KEY="$PWD/registrar_sign_priv.pem"
export REGISTRAR_PUB_KEY="$PWD/registrar_sign_pub.pem"
export ADMIN_PRIV_KEY="$PWD/admin_sign_priv.pem"
export ADMIN_PUB_KEY="$PWD/admin_sign_pub.pem"
export TALLIER_PRIV_KEY="$PWD/tallier_enc_priv.pem"
export TALLIER_PUB_KEY="$PWD/tallier_enc_pub.pem"
```

4. Run the server and follow the normal interactive flows in the client
   scripts. When keys are configured the new secure behaviors are used.

Notes, limitations, and next steps
- This is a demonstration implementation — it shows the patterns and
  integrates them into your existing code with minimal, readable changes.
- Production hardening to consider:
  - Use TLS (HTTPS) for all transport.
  - Store private keys securely (HSM, vault) — do not put them in the repo.
  - Add replay protection (timestamps and nonce cache) for signed messages.
  - Consider threshold cryptography (Shamir or MPC) for stronger multi-party
    decryption if you need more than 2 shares or more robust key sharing.

If you'd like, I can now:
- add a small `generate_keys.sh` helper (in `tests/keys/`) for local testing,
- add replay protection in server request verification, or
- switch from the XOR two-share design to Shamir secret-sharing for the
  symmetric key (done in this update).

This commit switched the two-share XOR scheme to a 3-of-3 Shamir secret
sharing scheme. The encryption now requires keys for Admin, Registrar and
Tallier. See the "Shamir" notes below and the code in `secure_utils.py`.

Shamir notes
- The symmetric AES key is split into 3 shares using Shamir over GF(256).
- Each share is encrypted to one party's RSA public key (admin, registrar,
  tallier). To decrypt, all three private keys are required and used to
  reconstruct the AES key and decrypt ballots.

If you want, I can now add the `generate_keys.sh` helper or implement
replay protection. Which do you prefer?
