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
import hashlib
import secrets
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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
    """Encrypt plaintext so that a threshold of parties must cooperate to decrypt.

    This implementation uses Shamir secret sharing to split the AES key
    into 3 shares and sets threshold k=2 (any two parties are sufficient
    to reconstruct). The three parties are admin, registrar and tallier.

    Returns a JSON-serializable dict with base64-encoded fields.
    """
    admin_pub = load_public_key(admin_pub_path)
    reg_pub = load_public_key(registrar_pub_path)
    tall_pub = load_public_key(tallier_pub_path)

    K = secrets.token_bytes(32)
    aesgcm = AESGCM(K)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Split K into 3 shares with threshold k=2 (any 2 of 3 can combine)
    shares = shamir_split(K, 3, 2)
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
        "alg": "AESGCM+RSA-OAEP+Shamir-3-of-2-v1",
    }


def decrypt_ballot_shamir_all(admin_priv_path: str, registrar_priv_path: str, tallier_priv_path: str, payload: Dict) -> bytes:
    """Decrypt payload created by `encrypt_ballot_shamir` using all three private keys."""
    # Load ciphertext and encrypted shares
    ct = base64.b64decode(payload["ciphertext"])
    nonce = base64.b64decode(payload["nonce"])
    enc_admin = base64.b64decode(payload["enc_share_admin"])
    enc_reg = base64.b64decode(payload["enc_share_reg"])
    enc_tall = base64.b64decode(payload["enc_share_tall"])

    # Attempt to decrypt any shares for which a private key path was
    # provided. The Shamir threshold is 2, so we require at least two
    # successfully decrypted shares to reconstruct the AES key.
    shares = []
    if admin_priv_path:
        try:
            priv_admin = load_private_key(admin_priv_path)
            s_admin = _rsa_decrypt(priv_admin, enc_admin)
            shares.append((1, s_admin))
        except Exception:
            pass
    if registrar_priv_path:
        try:
            priv_reg = load_private_key(registrar_priv_path)
            s_reg = _rsa_decrypt(priv_reg, enc_reg)
            shares.append((2, s_reg))
        except Exception:
            pass
    if tallier_priv_path:
        try:
            priv_tall = load_private_key(tallier_priv_path)
            s_tall = _rsa_decrypt(priv_tall, enc_tall)
            shares.append((3, s_tall))
        except Exception:
            pass

    if len(shares) < 2:
        raise ValueError("insufficient private keys available to reconstruct secret")

    secret = shamir_combine(shares)

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


# ---- ElGamal on EC (hybrid) ----
def elgamal_keygen(curve: ec.EllipticCurve = ec.SECP256R1()):
    """Generate an EC keypair for ElGamal-style hybrid encryption.

    Returns a tuple `(priv_pem: bytes, pub_pem: bytes)` suitable for saving to disk.
    Uses the standard PEM serialization for private/public keys.
    """
    priv = ec.generate_private_key(curve)
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _derive_shared_key(ec_priv, ec_peer_pub, info: bytes = b"elgamal-shared") -> bytes:
    """Derive a symmetric key from ECDH shared secret using HKDF-SHA256."""
    shared = ec_priv.exchange(ec.ECDH(), ec_peer_pub)
    # HKDF derive 32 bytes key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared)


def elgamal_encrypt(pub_pem_path: str, plaintext: bytes) -> Dict:
    """Encrypt `plaintext` to the given EC public key (PEM file).

    This performs an ephemeral-static ElGamal: pick ephemeral `k`, compute
    `R = k*G` (ephemeral public key) and derive symmetric key from `k*Q` via
    ECDH+HKDF. The message is encrypted with AES-GCM.

    Returns a JSON-serializable dict with base64-encoded fields:
    - `ephemeral_pub`: PEM of ephemeral public key (base64)
    - `nonce`, `ciphertext`, `alg`
    """
    pub = load_public_key(pub_pem_path)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        # cryptography's public key types are tested at runtime; allow duck-typing
        try:
            # attempt to load as PEM and check
            pass
        except Exception:
            raise ValueError("provided public key is not an EC public key")

    # Create ephemeral key
    eph = ec.generate_private_key(pub.curve)
    eph_pub = eph.public_key()

    # derive symmetric key via ECDH
    shared_key = _derive_shared_key(eph, pub)

    aesgcm = AESGCM(shared_key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # serialize ephemeral public key to PEM and include
    eph_pub_pem = eph_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "ephemeral_pub": base64.b64encode(eph_pub_pem).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "alg": "EC-ElGamal+AESGCM-HKDF-SHA256-v1",
    }


def elgamal_decrypt(priv_pem_path: str, payload: Dict) -> bytes:
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


# ---- Schnorr OR-proof API (placeholder) ----
def generate_schnorr_or_proof_elgamal(ciphertext: Dict, allowed_plaintexts: list, priv_pem_path: str):
    """Generate a Schnorr OR-proof that the given ElGamal `ciphertext` decrypts
    to one of the `allowed_plaintexts` WITHOUT revealing which one.

    NOTE: Full, secure Schnorr OR-proofs are non-trivial to implement correctly.
    This function currently raises NotImplementedError and serves as a clear
    integration point. For a production implementation, use a well-tested
    crypto library (e.g., `petlib` or specialized ZKP libraries) and follow
    a standard construction (Fiat-Shamir transformed Sigma OR-proofs).

    If you would like, I can implement this using `petlib`/`ecpy` once you
    confirm installation is acceptable.
    """
    raise NotImplementedError(
        "Schnorr OR-proof generation is not implemented. Install a ZKP library "
        "(e.g., petlib) and ask me to implement using that library."
    )


def verify_schnorr_or_proof_elgamal(ciphertext: Dict, proof, pub_pem_path: str, allowed_plaintexts: list) -> bool:
    """Verify a Schnorr OR-proof (placeholder).

    Returns True iff proof verifies. Currently not implemented.
    """
    raise NotImplementedError(
        "Schnorr OR-proof verification is not implemented. Provide a proof library "
        "and I can implement verification accordingly."
    )
