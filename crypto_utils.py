import os
import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
G = 2

def int_to_b64(n: int) -> str:
    return base64.b64encode(n.to_bytes((n.bit_length()+7)//8, 'big')).decode()

def b64_to_int(s: str) -> int:
    b = base64.b64decode(s.encode())
    return int.from_bytes(b, 'big')

def hkdf_keys(shared_secret: int, salt: bytes = b"dh-handshake", info: bytes = b"client-server") -> Tuple[bytes, bytes]:
    """Derive separate AES and HMAC keys from the raw shared secret using HKDF-SHA256."""
    ss_bytes = shared_secret.to_bytes((shared_secret.bit_length()+7)//8, 'big')
    okm = HKDF(master=ss_bytes, key_len=64, salt=salt, hashmod=SHA256, context=info)
    return okm[:32], okm[32:]

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }

def aes_gcm_decrypt(key: bytes, enc: dict, aad: bytes = b"") -> bytes:
    nonce = base64.b64decode(enc["nonce"])
    ciphertext = base64.b64decode(enc["ciphertext"])
    tag = base64.b64decode(enc["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

def hmac_sha256(key: bytes, data: bytes) -> str:
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return base64.b64encode(h.digest()).decode()

def validate_file(path: str, max_bytes: int = 10 * 1024 * 1024) -> Tuple[str, int, str]:
    """Security checks: existence, size, extension/type hint. Returns (safe_name, size, mime)."""
    p = os.path.abspath(path)
    if not os.path.exists(p):
        raise FileNotFoundError(f"File not found: {path}")
    size = os.path.getsize(p)
    if size <= 0:
        raise ValueError("Empty file not allowed.")
    if size > max_bytes:
        raise ValueError(f"File over size limit {max_bytes} bytes.")
    safe_name = os.path.basename(p)
    mime = mimetype_from_name(safe_name)
    return safe_name, size, mime

def mimetype_from_name(name: str) -> str:
    import mimetypes
    m, _ = mimetypes.guess_type(name)
    return m or "application/octet-stream"
