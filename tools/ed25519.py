"""Ed25519 signing and verifying (the "key"), standard library only.

The block between the markers is the RFC 8032 reference implementation
(pure Python, with an iterative scalar multiply so it never hits the recursion
limit). It is checked against the official RFC 8032 test vectors in
tests/test_keys.py. Do not change it without re-running those tests.

ed25519_verify is added on top of the reference signing code. It is written fail
closed: any malformed input returns False, never raises, never "maybe".

Note: pure Python, not constant-time. Fine for signing plugs on your own
machine; not a defence against someone timing your CPU.
"""
import hashlib

# ---- RFC 8032 REFERENCE START ----
_b = 256
_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(P, e):
    """Iterative double-and-add.

    The reference version recurses once per bit, which on a 256-bit scalar is
    256 frames deep and trips the default recursion limit on some builds --
    including, of course, phones.
    """
    Q = (0, 1)
    N = P
    while e > 0:
        if e & 1:
            Q = _edwards(Q, N)
        N = _edwards(N, N)
        e >>= 1
    return Q


def _encodeint(y):
    return y.to_bytes(32, "little")


def _encodepoint(P):
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _secret_scalar(h):
    return 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))


def _Hint(m):
    return int.from_bytes(_H(m), "little")


def ed25519_public_key(seed):
    """32-byte seed -> 32-byte public key."""
    h = _H(seed)
    return _encodepoint(_scalarmult(_B, _secret_scalar(h)))


def ed25519_sign(message, seed, public_key):
    """Detached 64-byte signature, same as cryptography's Ed25519 sign()."""
    h = _H(seed)
    a = _secret_scalar(h)
    r = _Hint(h[32:64] + message)
    R = _scalarmult(_B, r)
    encR = _encodepoint(R)
    S = (r + _Hint(encR + public_key + message) * a) % _l
    return encR + _encodeint(S)
# ---- RFC 8032 REFERENCE END ----


def _decodepoint(s):
    """32 bytes -> curve point. Raises ValueError on anything non-canonical."""
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    n = int.from_bytes(s, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= _q:
        raise ValueError("non-canonical y")
    x = _xrecover(y)
    if x == 0 and sign:
        raise ValueError("invalid sign bit")
    if (x & 1) != sign:
        x = _q - x
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _q != 0:
        raise ValueError("point not on curve")
    return (x, y)


def ed25519_verify(signature, message, public_key):
    """True only if signature is a valid Ed25519 signature of message by public_key."""
    try:
        if not (isinstance(signature, bytes) and isinstance(public_key, bytes) and isinstance(message, bytes)):
            return False
        if len(signature) != 64 or len(public_key) != 32:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
        S = int.from_bytes(signature[32:], "little")
        if S >= _l:
            return False
        h = _Hint(signature[:32] + public_key + message)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False
