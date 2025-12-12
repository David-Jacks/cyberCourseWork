import secrets
import random

# ---- GF(256) Precomputed Tables ----
_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256

def _init_gf_tables():
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


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError()
    return _GF256_EXP[255 - _GF256_LOG[a]]


def _eval_poly(coeffs, x):
    result = 0
    power = 1
    for c in coeffs:
        result = _gf_add(result, _gf_mul(c, power))
        power = _gf_mul(power, x)
    return result


def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder="big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def is_probable_prime(n: int, rounds: int = 8) -> bool:
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


def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate


def shamir_split(secret: bytes, n: int, k: int):
    if not (1 < k <= n <= 255):
        raise ValueError("invalid parameters for shamir_split")
    shares = [bytearray(len(secret)) for _ in range(n)]
    for idx, s_byte in enumerate(secret):
        coeffs = [s_byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1
            shares[i][idx] = _eval_poly(coeffs, x)
    return [(i + 1, bytes(shares[i])) for i in range(n)]


def shamir_combine(shares):
    if len(shares) == 0:
        return b""
    k = len(shares)
    length = len(shares[0][1])
    secret = bytearray(length)
    xs = [s[0] for s in shares]
    for pos in range(length):
        y_values = [s[1][pos] for s in shares]
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
    if not (1 < k <= n <= 255):
        raise ValueError("invalid parameters for shamir split")
    L = len(secret)
    CHUNK_SIZE = 128
    chunks = [secret[i:i+CHUNK_SIZE] for i in range(0, L, CHUNK_SIZE)]
    m = len(chunks)
    per_chunk_share_vals = []
    per_chunk_share_len = []
    for chunk in chunks:
        clen = len(chunk)
        secret_int = bytes_to_int(chunk)
        bits = clen * 8
        candidate = 1 << bits
        p = next_probable_prime_at_least(candidate)
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
        share_len = (p.bit_length() + 7) // 8
        per_chunk_share_len.append(share_len)
    shares = []
    for i in range(n):
        parts = []
        parts.append(int_to_bytes(L, 4))
        parts.append(int_to_bytes(CHUNK_SIZE, 2))
        parts.append(int_to_bytes(m, 2))
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
    if len(shares) == 0:
        return b""
    first = shares[0][1]
    L = bytes_to_int(first[0:4])
    CHUNK_SIZE = bytes_to_int(first[4:6])
    m = bytes_to_int(first[6:8])
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
        expected_len = CHUNK_SIZE if cidx < m - 1 else (L - CHUNK_SIZE * (m - 1))
        recovered_chunks.append(int_to_bytes(secret_chunk_int, expected_len))
    return b"".join(recovered_chunks)


def split_private_key_shares(priv_path: str, n: int, k: int):
    with open(priv_path, "rb") as f:
        pem = f.read()
    try:
        return _int_shamir_split(pem, n, k)
    except Exception:
        return shamir_split(pem, n, k)


def combine_private_key_shares(shares):
    try:
        return _int_shamir_combine(shares)
    except Exception:
        return shamir_combine(shares)
