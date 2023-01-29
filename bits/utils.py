import base64
import hashlib
import math
import re
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from bits.base58 import base58check
from bits.base58 import base58check_decode
from bits.bips.bip173 import segwit_addr
from bits.ecmath import point_is_on_curve
from bits.ecmath import point_scalar_mul
from bits.ecmath import SECP256K1_Gx
from bits.ecmath import SECP256K1_Gy
from bits.ecmath import SECP256K1_N
from bits.ecmath import sub_mod_p
from bits.ecmath import y_from_x
from bits.pem import decode_key
from bits.pem import encode_parsed_asn1
from bits.pem import parse_asn1


def pubkey(x: int, y: int, compressed=False) -> bytes:
    """
    Returns SEC1 pubkey from point (x, y)
    """
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    else:
        prefix = b"\x04"
        return prefix + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def privkey_int(privkey_: bytes) -> int:
    assert len(privkey_) == 32
    p = int.from_bytes(privkey_, "big")
    assert p > 0 and p < SECP256K1_N, f"private key not in range(1, N): {p}"
    return p


def compute_point(privkey_: bytes) -> Tuple[int]:
    """
    Compute (x, y) public key point from private key
    """
    k = privkey_int(privkey_)
    return point_scalar_mul(k, (SECP256K1_Gx, SECP256K1_Gy))


def point(pubkey_: bytes) -> Tuple[int]:
    """
    Return (x, y) point from SEC1 public key
    """
    assert len(pubkey_) == 33 or len(pubkey_) == 65
    version = pubkey_[0]
    payload = pubkey_[1:]
    x = int.from_bytes(payload[:32], "big")
    if version == 2:
        # compressed, y
        y = y_from_x(x)[0]
    elif version == 3:
        # compressed, -y
        y = y_from_x(x)[1]
    elif version == 4:
        # uncompressed
        y = int.from_bytes(payload[32:], "big")
    else:
        raise ValueError(f"unrecognized version: {version}")
    assert point_is_on_curve(x, y), "invalid pubkey"
    return (x, y)


def compressed_pubkey(pubkey_: bytes) -> bytes:
    """
    Returns:
        compressed pubkey from (un)compressed pubkey
    """
    assert len(pubkey_) == 33 or len(pubkey_) == 65
    prefix = pubkey_[0:1]
    if prefix in [b"\x02", b"\x03"]:
        return pubkey_
    elif prefix == b"\x04":
        return pubkey(*point(pubkey_), compressed=True)
    else:
        raise ValueError(f"unrecognized prefix {prefix}")


def pubkey_hash(pubkey_: bytes) -> bytes:
    """
    Returns pubkeyhash as used in P2PKH scriptPubKey
    e.g. RIPEMD160(SHA256(pubkey_))
    """
    hash_256 = hashlib.sha256(pubkey_).digest()
    ripe_hash = hashlib.new("ripemd160", hash_256).digest()
    return ripe_hash


def script_hash(redeem_script: bytes) -> bytes:
    return hashlib.new("ripemd160", redeem_script).digest()


def compact_size_uint(integer: int) -> bytes:
    """
    https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers
    """
    if integer < 0:
        raise ValueError("signed integer")
    elif integer >= 0 and integer <= 252:
        return integer.to_bytes(1, "little")
    elif integer >= 253 and integer <= 0xFFFF:
        return b"\xfd" + integer.to_bytes(2, "little")
    elif integer >= 0x10000 and integer <= 0xFFFFFFFF:
        return b"\xfe" + integer.to_bytes(4, "little")
    elif integer >= 0x100000000 and integer <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + integer.to_bytes(8, "little")


def parse_compact_size_uint(payload: bytes) -> Tuple[int, bytes]:
    """
    This function expects a compact size uint at the beginning of payload.
    Since compact size uints are variable in size, this function
    will observe the first byte, parse the necessary subsequent bytes,
    and return, as a tuple, the parsed integer followed by the rest of the
    payload (i.e. the remaining unparsed payload)
    """
    first_byte = payload[0]
    if first_byte == 255:
        integer = int.from_bytes(payload[1:9], "little")
        payload = payload[9:]
    elif first_byte == 254:
        integer = int.from_bytes(payload[1:5], "little")
        payload = payload[5:]
    elif first_byte == 253:
        integer = int.from_bytes(payload[1:3], "little")
        payload = payload[3:]
    else:
        integer = first_byte
        payload = payload[1:]
    return integer, payload


def s_hash(msg: bytes) -> bytes:
    """
    Single sha256 hash of msg
    """
    return hashlib.sha256(msg).digest()


def d_hash(msg: bytes) -> bytes:
    """
    Double sha256 hash of msg
    """
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def to_bitcoin_address(
    payload: bytes, addr_type: str = "p2pkh", network: str = None
) -> bytes:
    """
    Encode payload as bitcoin address invoice
    Args:
        payload: bytes, pubkey_hash (p2pkh) or script_hash (p2sh)
        addr_type: str, address type ("p2pkh" or "p2sh")
        network: str, `mainnet` or `testnet`
    Returns:
        base58 encoded bitcoin address
    """
    assert network in ["mainnet", "testnet"], f"unrecognized network: {network}"
    assert addr_type in ["p2pkh", "p2sh"], f"unrecognized address type: {addr_type}"
    if network == "mainnet" and addr_type == "p2pkh":
        version = b"\x00"
    elif network == "testnet" and addr_type == "p2pkh":
        version = b"\x6f"
    elif network == "mainnet" and addr_type == "p2sh":
        version = b"\x05"
    elif network == "testnet" and addr_type == "p2sh":
        version = b"\xc4"
    return base58check(version + payload)


def ensure_sig_low_s(sig_: bytes) -> bytes:
    """
    Ensure DER encoded signature has low enough s value
    https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures

    OpenSSL does not ensure this by default
    https://bitcoin.stackexchange.com/a/59826/135678
    Apparently, Bitcoin Core used to do this to get around it
    https://github.com/bitcoin/bitcoin/blob/v0.9.0/src/key.cpp#L204L224

    Essentially just use s = N - s if s > N / 2
    """
    parsed = parse_asn1(sig_)
    # r_val = int.from_bytes(parsed[0][2][0][2], "big")
    r_len = parsed[0][2][0][1]
    s_val = int.from_bytes(parsed[0][2][1][2], "big")
    s_len = parsed[0][2][1][1]
    if s_val > SECP256K1_N // 2 or s_val < 1:
        # s_val = SECP256K1_N - s_val
        s_val = sub_mod_p(0, s_val, p=SECP256K1_N)
        parsed[0][2][1][2] = s_val.to_bytes(32, "big")
        parsed[0][2][1][1] = 32
        parsed[0][1] = 32 + r_len + 4
        encoded = encode_parsed_asn1(parsed[0])
        return encoded
    return sig_


def pubkey_from_pem(pem_: bytes):
    decoded_key = decode_key(pem_)
    if len(decoded_key) == 2:
        return decoded_key[1]
    return decoded_key


def wif(
    privkey_: bytes,
    compressed_pubkey: bool = True,
    network: str = "mainnet",
) -> bytes:
    """
    WIF encoding
    # https://en.bitcoin.it/wiki/Wallet_import_format
    # https://river.com/learn/terms/w/wallet-import-format-wif/
    Args:
        privkey_: bytes, private key
        compressed_pubkey: bool, corresponds to a compressed pubkey
        network: str, mainnet or testnet
    """
    if network.lower() == "mainnet":
        prefix = b"\x80"
    elif network.lower() == "testnet":
        prefix = b"\xef"
    else:
        raise ValueError(f"unrecognized network: {network}")
    wif = prefix + privkey_
    if compressed_pubkey:
        wif += b"\x01"
    return base58check(wif)


def wif_decode(wif_: bytes) -> Tuple[bytes, bool]:
    return base58check_decode(wif_)
