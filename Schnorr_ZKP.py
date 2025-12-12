import hashlib
import secrets

# ---------------------- Utilities ----------------------
def H_bytes(*parts):
    """Hash helper returning an integer from SHA-256 over concatenated parts."""
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, int):
            part = str(part).encode()
        elif isinstance(part, str):
            part = part.encode()
        elif isinstance(part, bytes):
            part = part
        else:
            part = str(part).encode()
        h.update(part)
    return int(h.hexdigest(), 16)

def rand_range(n):
    """Return a random integer in [1, n-1] using secrets."""
    if n <= 2:
        return 1
    return secrets.randbelow(n - 1) + 1

#This function helpes to che
def is_probable_prime(n, k=8):
    """Miller-Rabin probabilistic primality test. k rounds (default 8)."""
    if n < 2:
        return False
    # small primes quick check
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # random in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_safe_prime(bit_length=256, max_tries=1000):
    """
    Generate a safe prime p where p = 2*q + 1 and q is prime.
    bit_length is size of p in bits. Smaller values are fast but insecure.
    """
    if bit_length < 32:
        raise ValueError("bit_length too small for useful primes")
    for attempt in range(max_tries):
        # generate random odd candidate for q of size bit_length-1
        q = secrets.randbits(bit_length - 1) | (1 << (bit_length - 2)) | 1
        if not is_probable_prime(q):
            continue
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q
    raise RuntimeError("Failed to generate safe prime after many tries")

def find_generator(p, q):
    """
    Find a generator g of the subgroup of order q in Z_p*.
    For safe prime p=2q+1, choose g with g^q mod p == 1 and g^2 mod p != 1.
    """
    for _ in range(1000):
        g = secrets.randbelow(p - 3) + 2
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            return g
    raise RuntimeError("Failed to find generator")

# ---------------------- Group / Key functions ----------------------
def generate_group(bit_length=256):
    """
    Generate (p, q, g) where p is safe prime (p=2q+1), q is prime, and
    g is generator of subgroup of order q. bit_length is size of p in bits.
    """
    p, q = generate_safe_prime(bit_length)
    g = find_generator(p, q)
    return {"p": p, "q": q, "g": g}

def voter_secret_key():
    return secrets.randbelow(900) + 100

def voter_public_key(x, p, g):
    return pow(g, x, p)


def keygen(p, q, g):
    """
    Generate secret key x in [1, q-1] and public h = g^x mod p.
    Returns (x, h).
    """
    x = rand_range(q)
    h = pow(g, x, p)
    return x, h


# ---------------------- Schnorr NIZK (Fiat-Shamir) ----------------------
def schnorr_nizk_prove(x, p, q, g, message=b""):
    r = rand_range(q)
    t = pow(g, r, p)
    h = pow(g, x, p)
    c = H_bytes(t, h, message) % q
    s = (r + c * x) % q
    return {"t": t, "c": c, "s": s, "h": h}


def schnorr_nizk_verify(h, t, c, s, p, q, g, message=b""):
    c_expected = H_bytes(t, h, message) % q
    if c != c_expected:
        return False
    left = pow(g, s, p)
    right = (t * pow(h, c, p)) % p
    return left == right


def voter_generate_proof(x, p, q, g, message=b""):
    return schnorr_nizk_prove(x, p, q, g, message)


def voter_verify_proof(h, t, c, s, p, q, g, message=b""):
    return schnorr_nizk_verify(h, t, c, s, p, q, g, message)


# functions to serialise proofs and send over network
def serialize_proof(proof):
    """Serialize proof dict to tuple of hex strings for easy transport."""
    return (hex(proof["t"]), hex(proof["c"]), hex(proof["s"]), hex(proof["h"]))

def deserialize_proof(t_hex, c_hex, s_hex, h_hex):
    """Deserialize hex strings back to integers (t, c, s, h)."""
    return (int(t_hex, 16), int(c_hex, 16), int(s_hex, 16), int(h_hex, 16))

