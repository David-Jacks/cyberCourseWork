"""Cryptographic utilities for the voting system.

This module provides helper functions used by the example code in this
repository. It intentionally keeps a simple, explicit API:

- hashing: `hash_id` (SHA256 hex) used to store non-reversible voter handles
- signing: Ed25519 sign/verify helpers for short signatures
- encryption: hybrid AES-GCM + RSA-OAEP helpers implementing a two-share
  split of the symmetric key so that BOTH the Registrar and the Tallier must
  provide their private keys to reconstruct the AES key and decrypt ballots.

Notes:
- This code depends on the `cryptography` library. Install with:
    pip install cryptography
- Keys are loaded from PEM files. The app looks for paths in environment
  variables where appropriate (see callers in the codebase).
"""

import os
import json
import base64
import hashlib
import secrets
from typing import Tuple, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def hash_id(voter_id: str) -> str:
    """Return SHA-256 hex digest of the provided voter identifier.

    This is used to avoid storing raw identifiers in the server database.
    The Registrar keeps the mapping between real id and hash off-server.
    """
    if voter_id is None:
        return None
    return hashlib.sha256(voter_id.encode("utf-8")).hexdigest()


def load_private_key(path: str, password: bytes = None):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())


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
    raise NotImplementedError("use encrypt_ballot_shamir for multi-party decryption")


def decrypt_ballot_with_both(registrar_priv_path: str, tallier_priv_path: str, payload: Dict) -> bytes:
    """Given both private keys and an encrypted payload (as produced by
    `encrypt_ballot_for_two`), return the decrypted plaintext bytes.
    """
    # NOTE: deprecated. Use `decrypt_ballot_shamir_all` which supports
    # multi-party Shamir reconstruction.
    raise NotImplementedError("use decrypt_ballot_shamir_all")


# ---- Shamir secret sharing over GF(256) ----
# We implement Shamir secret sharing on bytes using arithmetic in GF(256)
# with the AES polynomial (0x11b). This allows splitting an arbitrary byte
# string into N shares with threshold K. Each share is the same length as
# the secret (byte-wise sharing).

_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256

def _init_gf_tables():
    # generate exponent/log tables using AES polynomial 0x11b
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


_init_gf_tables()


def _gf_add(a: int, b: int) -> int:
    return a ^ b


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]


def _gf_pow(a: int, power: int) -> int:
    if power == 0:
        return 1
    if a == 0:
        return 0
    return _GF256_EXP[(_GF256_LOG[a] * power) % 255]


def _gf_inv(a: int) -> int:
    # multiplicative inverse in GF(256)
    if a == 0:
        raise ZeroDivisionError()
    return _GF256_EXP[255 - _GF256_LOG[a]]


def _eval_poly(coeffs, x):
    # coeffs: list of ints (byte values), evaluate polynomial at x in GF
    result = 0
    power = 1
    for c in coeffs:
        result = _gf_add(result, _gf_mul(c, power))
        power = _gf_mul(power, x)
    return result


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


def encrypt_ballot_shamir(admin_pub_path: str, registrar_pub_path: str, tallier_pub_path: str, plaintext: bytes) -> Dict:
    """Encrypt plaintext so that all three parties (admin, registrar, tallier)
    must cooperate to decrypt (3-of-3 Shamir).

    Steps:
    - generate random AES-256 key K
    - AES-GCM encrypt plaintext with K
    - split K into 3 shares with shamir_split (n=3,k=3)
    - encrypt each share with the corresponding RSA public key
    """
    admin_pub = load_public_key(admin_pub_path)
    reg_pub = load_public_key(registrar_pub_path)
    tall_pub = load_public_key(tallier_pub_path)

    K = secrets.token_bytes(32)
    aesgcm = AESGCM(K)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    shares = shamir_split(K, 3, 3)
    # shares are [(1, b1), (2, b2), (3, b3)] map to admin/reg/tall
    enc_admin = _rsa_encrypt(admin_pub, shares[0][1])
    enc_reg = _rsa_encrypt(reg_pub, shares[1][1])
    enc_tall = _rsa_encrypt(tall_pub, shares[2][1])

    return {
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "enc_share_admin": base64.b64encode(enc_admin).decode("ascii"),
        "enc_share_reg": base64.b64encode(enc_reg).decode("ascii"),
        "enc_share_tall": base64.b64encode(enc_tall).decode("ascii"),
        "alg": "AESGCM+RSA-OAEP+Shamir-3-of-3-v1",
    }


def decrypt_ballot_shamir_all(admin_priv_path: str, registrar_priv_path: str, tallier_priv_path: str, payload: Dict) -> bytes:
    """Decrypt payload created by `encrypt_ballot_shamir` using all three private keys."""
    priv_admin = load_private_key(admin_priv_path)
    priv_reg = load_private_key(registrar_priv_path)
    priv_tall = load_private_key(tallier_priv_path)

    ct = base64.b64decode(payload["ciphertext"])
    nonce = base64.b64decode(payload["nonce"])
    enc_admin = base64.b64decode(payload["enc_share_admin"])
    enc_reg = base64.b64decode(payload["enc_share_reg"])
    enc_tall = base64.b64decode(payload["enc_share_tall"])

    s_admin = _rsa_decrypt(priv_admin, enc_admin)
    s_reg = _rsa_decrypt(priv_reg, enc_reg)
    s_tall = _rsa_decrypt(priv_tall, enc_tall)

    # combine shares (x values 1,2,3)
    secret = shamir_combine([(1, s_admin), (2, s_reg), (3, s_tall)])

    aesgcm = AESGCM(secret)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt


def encrypt_for_registrar(registrar_pub_path: str, plaintext: bytes) -> str:
    """Encrypt small plaintext (e.g., a name) for the Registrar only.

    Returns base64 ciphertext.
    """
    pub = load_public_key(registrar_pub_path)
    return base64.b64encode(_rsa_encrypt(pub, plaintext)).decode("ascii")


def decrypt_for_registrar(registrar_priv_path: str, b64cipher: str) -> bytes:
    priv = load_private_key(registrar_priv_path)
    return _rsa_decrypt(priv, base64.b64decode(b64cipher))
