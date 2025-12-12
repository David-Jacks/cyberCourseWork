# This is my file for my helper functions and basic cryptographic operations.
import base64
import os
import hashlib
import secrets
from typing import Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


#my default url
DEFAULT_HOST = "http://localhost:5000"

#will set my default time out for requests to be 5
DEFAULT_TIMEOUT = 5.0

#function loads keys as environment variables at runtime
def _maybe_load_keys_env():
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


# ---- Hashing ----
# Function to hash voters ID.
def hash_id(voter_id: str) -> str:
    """Return SHA-256 hex digest of the provided voter identifier.

    This is used to avoid storing raw identifiers in the server database.
    The Registrar keeps the mapping between real id and hash off-server.
    """
    if voter_id is None:
        return None
    data = voter_id.encode("utf-8")
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
    return rsa_encrypt_to_b64(pub_ref, plaintext)


# ---- Ballot Encryption ----

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



