"""Cryptographic utilities for the voting system.

This module provides helper functions used by the example code in this
repository. It intentionally keeps a simple, explicit API:

- hashing: `hash_id` (SHA256 hex) used to store non-reversible voter handles
- signing: Ed25519 sign/verify helpers for short signatures
- encryption: hybrid AES-GCM + RSA-OAEP helpers implementing a two-share
  split of the symmetric key so that BOTH the Registrar and the Tallier must
  provide their private keys to reconstruct the AES key and decrypt ballots.


"""

import base64
import os
import hashlib
import secrets
import random
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---- GF(256) Precomputed Tables ----
# These tables are used for efficient arithmetic in GF(256).
_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256

def _init_gf_tables():
    """Initialize GF(256) exponent and logarithm tables using AES polynomial 0x11b."""
    poly = 0x11b
    x = 1
    for i in range(255):
        _GF256_EXP[i] = x
        _GF256_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= poly
    for i in range(255, 512):
        _GF256_EXP[i] = _GF256_EXP[i - 255]

# Initialize the tables at module load time.
_init_gf_tables()


# ---- Grouped Cryptographic Implementations ----

# ---- Hashing ----
# Functions related to hashing voter identifiers.
def hash_id(voter_id: str) -> str:
    """Return SHA-256 hex digest of the provided voter identifier.

    This is used to avoid storing raw identifiers in the server database.
    The Registrar keeps the mapping between real id and hash off-server.
    """
    if voter_id is None:
        return None
    # Use an optional server-side pepper to make preimage/guessing attacks
    # harder: the pepper should be kept secret on the server (env var
    # HASH_PEPPER). This preserves deterministic hashing while preventing
    # attackers from precomputing hashes for guessed IDs.
    import os
    pepper = os.environ.get("HASH_PEPPER", "")
    data = (voter_id + "|" + pepper).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---- Key Loading ----
# Functions for loading private and public keys from PEM files.
def load_private_key(path: str, password: bytes = None):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)


def load_public_key(path: str):
    # Accept a filesystem path, a raw PEM string, or a base64-encoded PEM
    if os.path.exists(path):
        with open(path, "rb") as f:
            return load_pem_public_key(f.read())
    b = path.encode("utf-8")
    if b.strip().startswith(b"-----BEGIN"):
        return load_pem_public_key(b)
    # try base64-decoded PEM
    try:
        decoded = base64.b64decode(path)
        if decoded.strip().startswith(b"-----BEGIN"):
            return load_pem_public_key(decoded)
    except Exception:
        pass
    raise ValueError("could not interpret public key reference")


# ---- Signing and Verification ----
# Functions for signing and verifying data using Ed25519.
def sign_ed25519(private_key_pem_path: str, data: bytes) -> bytes:
    """Sign `data` with an Ed25519 private key saved in PEM format.

    Caller should ensure the key exists. This helper raises on missing file.
    """
    priv = load_private_key(private_key_pem_path)
    # Accept both Ed25519 and RSA keys; prefer Ed25519 for signatures.
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        return priv.sign(data)
    # If the provided key is RSA, fall back to signing via PKCS1v15+SHA256
    # (not recommended for new designs, but kept for compatibility)
    if isinstance(priv, rsa.RSAPrivateKey):
        sig = priv.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return sig
    raise ValueError("unsupported private key type for signing")


def verify_ed25519(public_key_pem_path: str, data: bytes, signature: bytes) -> bool:
    pub = load_public_key(public_key_pem_path)
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, data)
            return True
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
    except Exception:
        return False
    return False


# ---- RSA Encryption and Decryption ----
# Functions for encrypting and decrypting data using RSA keys.
def _rsa_encrypt(pub, plaintext: bytes) -> bytes:
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _rsa_decrypt(priv, ciphertext: bytes) -> bytes:
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _load_public_from_ref(ref: str):
    """Load a public key from a file path, PEM string, or base64-encoded PEM.

    Returns a cryptography public key object.
    """
    # Path to file
    if os.path.exists(ref):
        return load_public_key(ref)
    # Raw PEM string
    b = ref.encode("utf-8")
    if b.strip().startswith(b"-----BEGIN"):
        return load_pem_public_key(b)
    # Base64-encoded PEM
    try:
        decoded = base64.b64decode(ref)
        if decoded.strip().startswith(b"-----BEGIN"):
            return load_pem_public_key(decoded)
    except Exception:
        pass
    raise ValueError("could not interpret public key reference")


def rsa_encrypt_to_b64(pub_ref: str, plaintext: bytes) -> str:
    """Encrypt `plaintext` with RSA public key referenced by `pub_ref`.

    `pub_ref` may be a path to a PEM file, a PEM string, or a base64-encoded
    PEM. Returns base64-encoded ciphertext (ASCII string).
    """
    pub = _load_public_from_ref(pub_ref)
    ct = _rsa_encrypt(pub, plaintext)
    return base64.b64encode(ct).decode("ascii")


def rsa_decrypt_from_b64(priv_path: str, b64_ciphertext: str) -> bytes:
    """Decrypt base64-encoded RSA ciphertext using private key at `priv_path`.

    Returns plaintext bytes.
    """
    priv = load_private_key(priv_path)
    ct = base64.b64decode(b64_ciphertext)
    return _rsa_decrypt(priv, ct)


def encrypt_for_registrar(pub_ref: str, plaintext: bytes) -> str:
    """Convenience wrapper used by Registrar to encrypt names for the Registrar key.

    Returns base64-encoded ciphertext (ASCII string).
    """
    return rsa_encrypt_to_b64(pub_ref, plaintext)


# ---- Ballot Encryption ----
# Functions for encrypting ballots using hybrid encryption schemes.
def encrypt_ballot_for_two(registrar_pub_path: str, tallier_pub_path: str, plaintext: bytes) -> Dict:
    """Encrypt `plaintext` so that BOTH Registrar and Tallier private keys are
    required to decrypt.

    Method:
    - Generate a random 32-byte symmetric key K.
    - Choose a random 32-byte share K1 and compute K2 = K XOR K1.
    - Encrypt ballot with AES-GCM using K.
    - Encrypt K1 with Registrar's RSA public key and K2 with Tallier's RSA public key.

    Returns a JSON-serializable dict with base64-encoded fields.
    """
    # NOTE: deprecated in favor of Shamir-based `encrypt_ballot_shamir`.
    # This helper was intentionally removed; use `encrypt_ballot_shamir`.


def encrypt_ballot_with_election_pub(election_pub_path: str, plaintext: bytes) -> Dict:
    """Hybrid encrypt plaintext to election RSA public key.

    Returns a dict with base64-encoded AES-GCM ciphertext, nonce and
    the AES key encrypted with the election RSA public key.
    """
    pub = load_public_key(election_pub_path)
    # symmetric key
    K = secrets.token_bytes(32)
    aesgcm = AESGCM(K)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    enc_key = _rsa_encrypt(pub, K)
    return {
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "enc_key": base64.b64encode(enc_key).decode("ascii"),
        "alg": "AESGCM+RSA-OAEP-v1",
    }


def decrypt_ballot_with_election_priv(election_priv_path: str, payload: Dict) -> bytes:
    """Decrypt payload created by `encrypt_ballot_with_election_pub` using election private key."""
    ct = base64.b64decode(payload["ciphertext"])
    nonce = base64.b64decode(payload["nonce"])
    enc_key = base64.b64decode(payload["enc_key"])
    priv = load_private_key(election_priv_path)
    K = _rsa_decrypt(priv, enc_key)
    aesgcm = AESGCM(K)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt


# ---- Shamir Secret Sharing ----
# Functions for splitting and combining secrets using Shamir's scheme.
def shamir_split(secret: bytes, n: int, k: int):
    """Split `secret` into `n` shares with threshold `k` using Shamir over GF(256).

    Returns list of (x, share_bytes) where x is 1..255.
    """
    if not (1 < k <= n <= 255):
        raise ValueError("invalid parameters for shamir_split")
    shares = [bytearray(len(secret)) for _ in range(n)]
    # For each byte of secret, build random polynomial of degree k-1 with
    # constant term = secret_byte, then evaluate at x=1..n
    for idx, s_byte in enumerate(secret):
        # random coefficients for degree 1..k-1
        coeffs = [s_byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1
            shares[i][idx] = _eval_poly(coeffs, x)
    return [(i + 1, bytes(shares[i])) for i in range(n)]


def shamir_combine(shares):
    """Recombine shares produced by `shamir_split`.

    `shares` is a list of (x, share_bytes). All share_bytes must be same length.
    Returns the original secret bytes.
    """
    if len(shares) == 0:
        return b""
    k = len(shares)
    length = len(shares[0][1])
    secret = bytearray(length)

    xs = [s[0] for s in shares]

    for pos in range(length):
        y_values = [s[1][pos] for s in shares]
        # Lagrange interpolation at x=0 to recover constant term
        acc = 0
        for i in range(k):
            xi = xs[i]
            yi = y_values[i]
            num = 1
            den = 1
            for j in range(k):
                if i == j:
                    continue
                xj = xs[j]
                num = _gf_mul(num, xj)
                den = _gf_mul(den, _gf_add(xj, xi))
            lag = _gf_mul(num, _gf_inv(den))
            acc = _gf_add(acc, _gf_mul(yi, lag))
        secret[pos] = acc
    return bytes(secret)


def _int_shamir_split(secret: bytes, n: int, k: int):
    """Split secret bytes into n shares with threshold k using Shamir over integers mod prime.

    This implementation splits `secret` into fixed-size chunks and performs
    integer-Shamir on each chunk separately. This avoids searching for a
    single prime larger than a very large secret.

    Share format (per-share):
      [total_len:4][chunk_size:2][num_chunks:2][chunk1_share][chunk2_share]...

    Returns list of (x, share_bytes).
    """
    if not (1 < k <= n <= 255):
        raise ValueError("invalid parameters for shamir split")
    L = len(secret)
    # fixed chunk size (bytes). Reasonable tradeoff between prime search cost and number of chunks.
    CHUNK_SIZE = 128
    chunks = [secret[i:i+CHUNK_SIZE] for i in range(0, L, CHUNK_SIZE)]
    m = len(chunks)

    # For each chunk, pick a prime p >= 2^(8*len(chunk)) and perform Shamir on that integer.
    per_chunk_share_vals = []  # list of lists of ints: per_chunk_share_vals[chunk_idx][share_index]
    per_chunk_share_len = []
    for chunk in chunks:
        clen = len(chunk)
        secret_int = bytes_to_int(chunk)
        bits = clen * 8
        candidate = 1 << bits
        p = next_probable_prime_at_least(candidate)
        # create polynomial coefficients modulo p
        coeffs = [secret_int] + [random.randrange(0, p) for _ in range(k - 1)]
        share_vals = []
        for i in range(n):
            x = i + 1
            acc = 0
            xp = 1
            for c in coeffs:
                acc = (acc + (c * xp)) % p
                xp = (xp * x) % p
            share_vals.append((acc, p))
        per_chunk_share_vals.append(share_vals)
        # share length in bytes for this chunk (p bit length)
        share_len = (p.bit_length() + 7) // 8
        per_chunk_share_len.append(share_len)

    # Build share bytes for each of the n shares by concatenating per-chunk share values.
    # Header layout: total_len(4) | chunk_size(2) | num_chunks(2) |
    # for each chunk: share_len(2) | prime_len(2) | prime_bytes(prime_len)
    shares = []
    for i in range(n):
        parts = []
        parts.append(int_to_bytes(L, 4))
        parts.append(int_to_bytes(CHUNK_SIZE, 2))
        parts.append(int_to_bytes(m, 2))
        # include per-chunk share lengths and the prime for each chunk
        for cidx in range(m):
            share_len = per_chunk_share_len[cidx]
            p = per_chunk_share_vals[cidx][0][1]
            p_bytes = int_to_bytes(p, (p.bit_length() + 7) // 8)
            parts.append(int_to_bytes(share_len, 2))
            parts.append(int_to_bytes(len(p_bytes), 2))
            parts.append(p_bytes)
        for cidx in range(m):
            val, p = per_chunk_share_vals[cidx][i]
            share_len = per_chunk_share_len[cidx]
            parts.append(int_to_bytes(val, share_len))
        share_bytes = b"".join(parts)
        shares.append((i+1, share_bytes))
    return shares


def _int_shamir_combine(shares):
    """Combine shares created by `_int_shamir_split` and return original secret bytes."""
    if len(shares) == 0:
        return b""
    # parse header from first share
    first = shares[0][1]
    L = bytes_to_int(first[0:4])
    CHUNK_SIZE = bytes_to_int(first[4:6])
    m = bytes_to_int(first[6:8])
    # next per-chunk metadata: for each chunk: share_len(2) | prime_len(2) | prime_bytes
    per_chunk_share_len = []
    per_chunk_prime = []
    pos = 8
    for _ in range(m):
        share_len = bytes_to_int(first[pos:pos+2]); pos += 2
        prime_len = bytes_to_int(first[pos:pos+2]); pos += 2
        p_bytes = first[pos:pos+prime_len]; pos += prime_len
        per_chunk_share_len.append(share_len)
        per_chunk_prime.append(bytes_to_int(p_bytes))
    header_len = pos

    # Extract per-chunk share integers for each provided share
    xs = [s[0] for s in shares]
    k = len(shares)
    per_chunk_ys = [[] for _ in range(m)]
    for s in shares:
        b = s[1]
        pos = header_len
        for cidx in range(m):
            slen = per_chunk_share_len[cidx]
            chunk_bytes = b[pos:pos+slen]
            val = bytes_to_int(chunk_bytes)
            per_chunk_ys[cidx].append(val)
            pos += slen

    # Reconstruct each chunk via integer Lagrange interpolation modulo the stored prime
    recovered_chunks = []
    for cidx in range(m):
        ys = per_chunk_ys[cidx]
        p = per_chunk_prime[cidx]
        secret_chunk_int = 0
        for i in range(k):
            xi = xs[i]
            yi = ys[i]
            num = 1
            den = 1
            for j in range(k):
                if i == j:
                    continue
                xj = xs[j]
                num = (num * (-xj)) % p
                den = (den * (xi - xj)) % p
            inv_den = pow(den, -1, p)
            lag = (num * inv_den) % p
            secret_chunk_int = (secret_chunk_int + (yi * lag)) % p
        # determine expected length for this chunk
        expected_len = CHUNK_SIZE if cidx < m - 1 else (L - CHUNK_SIZE * (m - 1))
        recovered_chunks.append(int_to_bytes(secret_chunk_int, expected_len))

    return b"".join(recovered_chunks)


def split_private_key_shares(priv_path: str, n: int, k: int):
    """Load private key PEM bytes and split into `n` shares with threshold `k`.

    Returns list of (x, share_bytes).
    """
    with open(priv_path, "rb") as f:
        pem = f.read()
    # Prefer integer-Shamir splitting which works well for arbitrary-length
    # secrets and maps cleanly to integer polynomial operations.
    try:
        return _int_shamir_split(pem, n, k)
    except Exception:
        # Fallback: byte-wise Shamir
        return shamir_split(pem, n, k)


def combine_private_key_shares(shares):
    """Combine shares (list of (x, share_bytes)) to recover private key PEM bytes."""
    # Try integer-Shamir combine first (compatible with `_int_shamir_split`)
    try:
        return _int_shamir_combine(shares)
    except Exception:
        # Fallback to byte-wise Shamir recombination
        return shamir_combine(shares)


# ---- ElGamal Encryption ----
# Functions for ElGamal-style hybrid encryption using elliptic curves.
# def elgamal_keygen(curve: ec.EllipticCurve = ec.SECP256R1()):
#     """Generate an EC keypair for ElGamal-style hybrid encryption.

#     Returns a tuple `(priv_pem: bytes, pub_pem: bytes)` suitable for saving to disk.
#     Uses the standard PEM serialization for private/public keys.
#     """
#     priv = ec.generate_private_key(curve)
#     pub = priv.public_key()

#     priv_pem = priv.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.NoEncryption(),
#     )
#     pub_pem = pub.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     )
#     return priv_pem, pub_pem


# def _derive_shared_key(ec_priv, ec_peer_pub, info: bytes = b"elgamal-shared") -> bytes:
#     """Derive a symmetric key from ECDH shared secret using HKDF-SHA256."""
#     shared = ec_priv.exchange(ec.ECDH(), ec_peer_pub)
#     # HKDF derive 32 bytes key
#     hkdf = HKDF(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=None,
#         info=info,
#     )
#     return hkdf.derive(shared)


# def elgamal_encrypt(pub_pem_path: str, plaintext: bytes) -> Dict:
#     """Encrypt `plaintext` to the given EC public key (PEM file).

#     This performs an ephemeral-static ElGamal: pick ephemeral `k`, compute
#     `R = k*G` (ephemeral public key) and derive symmetric key from `k*Q` via
#     ECDH+HKDF. The message is encrypted with AES-GCM.

#     Returns a JSON-serializable dict with base64-encoded fields:
#     - `ephemeral_pub`: PEM of ephemeral public key (base64)
#     - `nonce`, `ciphertext`, `alg`
#     """
#     pub = load_public_key(pub_pem_path)
#     if not isinstance(pub, ec.EllipticCurvePublicKey):
#         # cryptography's public key types are tested at runtime; allow duck-typing
#         try:
#             # attempt to load as PEM and check
#             pass
#         except Exception:
#             raise ValueError("provided public key is not an EC public key")

#     # Create ephemeral key
#     eph = ec.generate_private_key(pub.curve)
#     eph_pub = eph.public_key()

#     # derive symmetric key via ECDH
#     shared_key = _derive_shared_key(eph, pub)

#     aesgcm = AESGCM(shared_key)
#     nonce = secrets.token_bytes(12)
#     ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

#     # serialize ephemeral public key to PEM and include
#     eph_pub_pem = eph_pub.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo,
#     )

#     return {
#         "ephemeral_pub": base64.b64encode(eph_pub_pem).decode("ascii"),
#         "nonce": base64.b64encode(nonce).decode("ascii"),
#         "ciphertext": base64.b64encode(ct).decode("ascii"),
#         "alg": "EC-ElGamal+AESGCM-HKDF-SHA256-v1",
#     }


# def elgamal_decrypt(priv_pem_path: str, payload: Dict) -> bytes:
    """Decrypt payload produced by `elgamal_encrypt` using private key PEM path."""
    priv = load_private_key(priv_pem_path)
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise ValueError("provided private key is not an EC private key")

    eph_pub_pem = base64.b64decode(payload["ephemeral_pub"])
    eph_pub = serialization.load_pem_public_key(eph_pub_pem)

    shared_key = _derive_shared_key(priv, eph_pub)
    aesgcm = AESGCM(shared_key)
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["ciphertext"])
    return aesgcm.decrypt(nonce, ct, associated_data=None)


# Schnorr OR-proofs are intentionally omitted from this module. If you
# require generation/verification of Schnorr OR-proofs for ElGamal ciphertexts,
# add a well-tested ZKP library (for example, `petlib`) and implement helper
# wrappers here. Implementing ZKPs by hand is error-prone and out of scope for
# this utilities module.

# ---- Helper Functions ----
# These functions are used internally by Shamir secret sharing and other cryptographic utilities.

def _eval_poly(coeffs, x):
    """Evaluate a polynomial at x using coefficients in GF(256)."""
    result = 0
    power = 1
    for c in coeffs:
        result = _gf_add(result, _gf_mul(c, power))
        power = _gf_mul(power, x)
    return result

def _gf_add(a: int, b: int) -> int:
    """Addition in GF(256) is XOR."""
    return a ^ b

def _gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(256) using precomputed tables."""
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]

def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(256)."""
    if a == 0:
        raise ZeroDivisionError()
    return _GF256_EXP[255 - _GF256_LOG[a]]

def int_to_bytes(i: int, length: int) -> bytes:
    """Convert an integer to a byte array of the specified length."""
    return i.to_bytes(length, byteorder="big")

def bytes_to_int(b: bytes) -> int:
    """Convert a byte array to an integer."""
    return int.from_bytes(b, byteorder="big")

def next_probable_prime_at_least(m: int) -> int:
    """Find the next probable prime greater than or equal to m."""
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate

def is_probable_prime(n: int, rounds: int = 8) -> bool:
    """Check if a number is a probable prime using the Miller-Rabin test."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
