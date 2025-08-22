from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2**15  # 32768
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
NONCE_LEN = 12

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))

def verify_key(password: str, salt: bytes, key: bytes) -> bool:
    try:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        kdf.verify(password.encode("utf-8"), key)
        return True
    except Exception:
        return False

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    # last 16 bytes are tag in AESGCM, but cryptography keeps them appended; we keep as one blob
    return nonce, ciphertext, b""  # tag is inside ciphertext

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

def new_salt() -> bytes:
    return os.urandom(16)

CHECK_MAGIC = b"vault-ok-v1"
def make_verifier(key: bytes) -> Tuple[bytes, bytes]:
    """Return (nonce, blob) where blob = AESGCM(nonce, CHECK_MAGIC)."""
    nonce, blob, _ = encrypt(key, CHECK_MAGIC)
    return nonce, blob

def verify_verifier(key: bytes, nonce: bytes, blob: bytes) -> bool:
    try:
        pt = decrypt(key, nonce, blob)
        return pt == CHECK_MAGIC
    except Exception:
        return False
