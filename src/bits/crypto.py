import hashlib


def hash160(msg: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(msg).digest()).digest()


def ripemd160(msg: bytes) -> bytes:
    return hashlib.new("ripemd160", msg).digest()


def sha256(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


def hash256(msg: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()
