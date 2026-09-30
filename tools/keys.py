"""Plug keys (Phase 3): make an Ed25519 key pair, sign, verify.

A key file holds the 32-byte secret seed as hex. It is the author's identity:
anyone with it can sign plugs as you. It never goes in the repo (.gitignore
blocks *.key and keys/), and the default place is outside the project.

Usage:
  python tools/keys.py new  NAME            make WORKZONE_HOME/keys/NAME.key, default ~/.workzone (refuses to overwrite)
  python tools/keys.py pub  KEYFILE         print the public key (safe to share)
  python tools/keys.py sign KEYFILE FILE    print a signature of FILE
  python tools/keys.py verify PUB FILE SIG  exit 0 if valid, 1 if not
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ed25519 import ed25519_public_key, ed25519_sign, ed25519_verify  # noqa: E402

# Same home as the other tools: WORKZONE_HOME if set, else ~/.workzone.
KEY_DIR = Path(os.environ.get("WORKZONE_HOME", Path.home() / ".workzone")) / "keys"
PREFIX = "ed25519:"


def new_key(path):
    """Create a new secret key file. Refuses to overwrite: losing a key loses an identity."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing key {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    # 'x' mode = create only, so a race can't overwrite either.
    with open(path, "x", encoding="ascii") as f:
        f.write(seed.hex() + "\n")
    return seed


def load_seed(path):
    text = Path(path).read_text(encoding="ascii").strip()
    seed = bytes.fromhex(text)
    if len(seed) != 32:
        raise ValueError(f"{path}: a key file must hold 64 hex characters")
    return seed


def public_key_str(seed):
    return PREFIX + ed25519_public_key(seed).hex()


def parse_public_key(s):
    """'ed25519:<64 hex>' -> 32 bytes. Raises ValueError on anything else."""
    if not isinstance(s, str) or not s.startswith(PREFIX):
        raise ValueError("public key must start with 'ed25519:'")
    raw = s[len(PREFIX):]
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise ValueError("public key must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def sign(seed, message):
    return ed25519_sign(message, seed, ed25519_public_key(seed))


def verify(public_key, message, signature):
    """public_key: 'ed25519:..' string or 32 bytes. Fails closed on bad input."""
    try:
        pk = parse_public_key(public_key) if isinstance(public_key, str) else public_key
    except ValueError:
        return False
    return ed25519_verify(signature, message, pk)


def main(argv):
    if len(argv) >= 2 and argv[0] == "new":
        path = KEY_DIR / f"{argv[1]}.key"
        seed = new_key(path)
        print(f"secret key saved: {path}  (keep it private, back it up)")
        print(f"public key:       {public_key_str(seed)}")
        return 0
    if len(argv) == 2 and argv[0] == "pub":
        print(public_key_str(load_seed(argv[1])))
        return 0
    if len(argv) == 3 and argv[0] == "sign":
        print(sign(load_seed(argv[1]), Path(argv[2]).read_bytes()).hex())
        return 0
    if len(argv) == 4 and argv[0] == "verify":
        try:
            sig = bytes.fromhex(argv[3])
        except ValueError:
            sig = b""
        ok = verify(argv[1], Path(argv[2]).read_bytes(), sig)
        print("VALID" if ok else "INVALID")
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
