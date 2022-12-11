import base64
import hashlib
import re
from typing import List
from typing import Tuple

from base58 import b58decode
from base58 import b58decode_check
from base58 import b58encode
from ecdsa import SECP256k1
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.der import UnexpectedDER


def pubkey(x: int, y: int, compressed=False) -> bytes:
    """
    Returns pubkey in hex from point (x, y),
    optionally SEC1 compressed
    """
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    else:
        prefix = b"\x04"
        return prefix + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def pubkey_from_pem(pem: bytes, compressed=False) -> bytes:
    """
    Return pubkey bytes from private or public pem
    """
    try:
        vk = VerifyingKey.from_pem(pem)
    except UnexpectedDER:
        vk = SigningKey.from_pem(pem).verifying_key
    return pubkey(vk.pubkey.point.x(), vk.pubkey.point.y(), compressed=compressed)


def point(pubkey_: bytes) -> Tuple[int]:
    """
    Return (x, y) from pubkey_ bytes encoding
    """
    vk = VerifyingKey.from_string(pubkey_, curve=SECP256k1)
    return vk.pubkey.point.x(), vk.pubkey.point.y()


def point_from_pubkey(pubkey_: bytes) -> Tuple[int]:
    """
    WIP
    """
    if pubkey_[0] not in [b"\x02", b"\x03", b"\x04"]:
        raise ValueError(f"unrecognized version byte: {pubkey_[0]}")
    x = int.from_bytes(pubkey_[1:33], "big")
    if pubkey_[0] == b"\x02":
        pass
    elif pubkey_[0] == b"\x03":
        pass
    else:
        # uncompressed
        x = int.from_bytes(pubkey_[1:33], "big")
        y = int.from_bytes(pubkey_[33:], "big")
    return (x, y)


def pubkey_hash(pubkey_: bytes) -> bytes:
    """
    Returns pubkeyhash as used in P2PKH scriptPubKey
    e.g. RIPEMD160(SHA256(pubkey_))
    """
    hash_256 = hashlib.sha256(pubkey_).digest()
    ripe_hash = hashlib.new("ripemd160", hash_256).digest()
    return ripe_hash


def base58check(version: bytes, payload: bytes) -> bytes:
    """
    Base58 check encoding used for bitcoin addresses

    Args:
        version: bytes, 0x00 for mainnet, 0x6f for testnet, etc.
        payload: bytes, payload, e.g. pubkey hash
    """
    version_payload = version + payload
    checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
    return b58encode(version_payload + checksum)


def decode_addr(baddr: str) -> Tuple[bytes, bytes]:
    decoded = b58decode_check(baddr)
    return decoded[0], decoded[1:]


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


def pub_point(priv_: int) -> Tuple[int]:
    """
    Return (x, y) public point on SECP256k1 curve, from priv_ key
    """
    sk = SigningKey.from_secret_exponent(priv_, curve=SECP256k1)
    return sk.verifying_key.pubkey.point.x(), sk.verifying_key.pubkey.point.y()


def d_hash(msg: bytes) -> bytes:
    """
    Double sha256 hash of msg
    """
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def pubkey_hash_from_p2pkh(baddr: bytes) -> bytes:
    """
    Return pubkeyhash from bitcoin address, with checksum verification
    """
    decoded_addr = b58decode(baddr)
    checksum = decoded_addr[-4:]
    checksum_check = hashlib.sha256(hashlib.sha256(decoded_addr[:-4]).digest()).digest()
    assert checksum == checksum_check[:4]
    return decoded_addr[1:-4]  # remove version byte and checksum


def to_bitcoin_address(
    pubkey_: bytes, addr_type: str = "pkh", network: str = None
) -> str:
    """
    Convert pubkey to bitcoin address
    Args:
        pubkey_: bytes, pubkey in hex
        addr_type: str, adress type
        network: str, `mainnet` or `testnet`
    Returns:
        base58 encoded bitcoin address
    """
    if addr_type.lower() == "pkh":
        key = pubkey_hash(pubkey_)
    elif addr_type.lower() == "pk":
        key = pubkey_
    elif addr_type.lower() == "wpkh":
        raise NotImplementedError
    else:
        raise ValueError(f"addr_type not recognized: {addr_type}")
    if network == "mainnet":
        version = b"\x00"
    elif network == "testnet":
        version = b"\x6f"
    else:
        raise ValueError(f"unrecognized network: {network}")
    return base58check(version, key).decode("ascii")


def decode_pem(pem: bytes) -> bytes:
    """
    Decode pem to der
    inspiration from ssl.PEM_cert_to_DER_cert
    but more general
    """
    pem_ = pem.strip()
    header_re = b"-----BEGIN .+-----"
    footer_re = b"-----END .+-----"
    header_search = re.search(header_re, pem_)
    if not header_search or header_search.start() != 0:
        raise ValueError("encoding error; must start with pem header")
    footer_search = re.search(footer_re, pem_)
    if not footer_search or footer_search.end() != len(pem_):
        raise ValueError("encoding error; must end with pem footer")
    d = pem_[header_search.end() : footer_search.start()].strip()
    return base64.decodebytes(d)


# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#tag
TAG_MAP = {
    0x02: "INTEGER",
    0x03: "BIT STRING",
    0x04: "OCTET STRING",
    0x05: "NULL",
    0x06: "OBJECT IDENTIFIER",
    0x0C: "UTF8String",
    0x10: "SEQUENCE (OF)",
    0x11: "SET (OF)",
}
# tag classes
#   bit 6: 1=constructed 0=primitive
#   | class            | bit 8 | bit 7 |
#    ------------------ ------- -------
#   | universal        |   0   |   0   |
#   | application      |   0   |   1   |
#   | context-specific |   1   |   0   |
#   | private          |   1   |   1   |
# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#tag-classes
TAG_CLASS_MAP = {
    0b00: "Universal",
    0b01: "Application",
    0b10: "Context-specific",
    0b11: "Private",
}


def parse_asn1(data: bytes):
    """
    Parse ASN.1 data
    Recursive for SEQUENCE (OF) tag
    """
    parsed = []
    while data:
        tag = data[0]
        length = data[1]
        value = data[2 : 2 + length]
        parsed.append(
            (
                (
                    TAG_MAP[tag & 0b00011111],
                    "Constructed" if tag & 0b00100000 else "Primitive",
                    TAG_CLASS_MAP[tag >> 6],
                ),
                length,
                parse_asn1(value)
                if tag & 0b00011111
                == list(filter(lambda key: TAG_MAP[key] == "SEQUENCE (OF)", TAG_MAP))[0]
                else value,
            )
        )
        data = data[2 + length :]
    return parsed
