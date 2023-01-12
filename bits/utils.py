import base64
import hashlib
import math
import re
from typing import List
from typing import Tuple
from typing import Union

from bits.base58 import base58check
from bits.base58 import base58check_decode
from bits.ecmath import point_is_on_curve
from bits.ecmath import point_scalar_mul
from bits.ecmath import SECP256K1_Gx
from bits.ecmath import SECP256K1_Gy
from bits.ecmath import SECP256K1_N
from bits.ecmath import sub_mod_p
from bits.ecmath import y_from_x


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
) -> str:
    """
    Encode payload as bitcoin address invoice
    Args:
        payload: bytes, pubkey_hash (p2pkh) or redeem_script (p2sh)
        addr_type: str, address type
        network: str, `mainnet` or `testnet`
    Returns:
        base58 encoded bitcoin address
    """
    if network == "mainnet" and addr_type == "p2pkh":
        version = b"\x00"
    elif network == "testnet" and addr_type == "p2pkh":
        version = b"\x6f"
    elif network == "mainnet" and addr_type == "p2sh":
        version = b"\x05"
    elif network == "testnet" and addr_type == "p2sh":
        version = b"\xc4"
    else:
        raise ValueError(
            f"unrecognized network ({network}) or address type ({addr_type})"
        )
    return base58check(version + payload).decode("ascii")


def decode_base64_pem(pem: bytes) -> bytes:
    """
    Decode pem base64 data
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


def decode_pem(pem_: bytes):
    """
    Decode pem and parse ASN.1
    """
    der = decode_base64_pem(pem_)
    return der


def encode_pem(
    der_: bytes,
    header: bytes = b"-----BEGIN CERTIFICATE-----",
    footer: bytes = b"-----END CERTIFICATE-----",
) -> bytes:
    return header + b"\n" + base64.encodebytes(der_) + b"\n" + footer


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


def decode_key(pem_: bytes) -> Union[Tuple[bytes, bytes], bytes]:
    """
    Decode from pem encoded EC private / public key
    Returns:
        (privkey, pubkey) or pubkey, respectively
    """
    decoded = decode_pem(pem_)
    parsed = parse_asn1(decoded)
    if parsed[0][2][0][2] == b"\x01":
        return parsed[0][2][1][2], parsed[0][2][3][2][0][2][1:]
    elif parsed[0][2][0][2][0][2] == "id-ecPublicKey":
        return parsed[0][2][1][2][1:]
    else:
        raise ValueError("could not identify data as private nor public key")


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
MAP_TAG = {value: key for key, value in TAG_MAP.items()}
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
MAP_CLASS_TAG = {value: key for key, value in TAG_CLASS_MAP.items()}


def encode_parsed_asn1_val(tag: int, parsed_val: Union[list, bytes]) -> bytes:
    encoded = b""
    if tag & 0x1F == MAP_TAG["SEQUENCE (OF)"]:
        for val in parsed_val:
            encoded += encode_parsed_asn1(val)
    elif tag & 0x1F == MAP_TAG["INTEGER"]:
        encoded += parsed_val
    return encoded


def encode_parsed_asn1(parsed_data: list) -> bytes:
    """
    Inverse of parse_asn1
    >>> sig = bytes.fromhex("3046022100807ebfaf104a08061044a11109873af5c16cfb2e4e4ec69b47bd4dfcf3b630d4022100bbc3387cc3c5fd83d672eee20c40161099f8df44e135ca96a9b8650dbcbfe1bc")
    >>> parsed = parse_asn1(sig)
    >>> encoded = encode_parsed_asn1(parsed[0])
    >>> assert sig == encoded
    """
    encoded = b""
    tag_tuple, length, parsed_data = parsed_data[0], parsed_data[1], parsed_data[2]
    tag, tag_constructed, tag_class = tag_tuple
    tag_int = MAP_TAG[tag]
    if tag_constructed == "Constructed":
        tag_int |= 0b00100000
    tag_int |= MAP_CLASS_TAG[tag_class] << 6
    encoded += tag_int.to_bytes(1, "big") + length.to_bytes(1, "big")
    encoded += encode_parsed_asn1_val(tag_int, parsed_data)
    return encoded


# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
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
            [
                [
                    TAG_MAP.get(tag & 0b00011111, tag & 0b00011111),
                    "Constructed" if tag & 0b00100000 else "Primitive",
                    TAG_CLASS_MAP[tag >> 6],
                ],
                length,
                parse_asn1_value(tag, value),
            ]
        )
        data = data[2 + length :]
    return parsed


def parse_asn1_value(tag: int, value: bytes):
    """
    Parse ASN.1 tag's value
    """
    tag_constructed = tag & 0b00100000
    tag_class = tag >> 6
    tag = tag & 0b00011111
    if tag == MAP_TAG["SEQUENCE (OF)"]:
        return parse_asn1(value)
    elif tag == MAP_TAG["OBJECT IDENTIFIER"]:
        oid = parse_oid(value)
        if oid == "1.2.840.10045.2.1":
            oid = "id-ecPublicKey"
        return oid
    elif tag_constructed:
        return parse_asn1(value)
    else:
        return value


def parse_oid(data: bytes) -> str:
    """
    >>> parse_oid(bytes.fromhex("2a8648ce3d0201"))
    '1.2.840.10045.2.1'
    """
    # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    # relevant OIDS:
    #   id-ecPublicKey: 1.2.840.10045.2.1
    nodes = []
    # 1st byte = node1 * 40 + node2
    first_byte = data[0]
    first_node = int(first_byte / 40)
    second_node = first_byte % 40
    nodes.append(first_node)
    nodes.append(second_node)
    data = data[1:]
    while data:
        i = 0
        first_byte = data[i]
        leftmost_bit = first_byte & 0b10000000
        if leftmost_bit:
            # https://stackoverflow.com/a/24720842
            vlq_bytes = [first_byte]
            while leftmost_bit:
                i += 1
                next_byte = data[i]
                vlq_bytes.append(next_byte)
                leftmost_bit = next_byte & 0b10000000
            data = data[i + 1 :]
            # concatenate lower 7 bits of each vlq_byte, read as int
            # vlq_bytes = [vlq_byte & 0x7F for vlq_byte in vlq_bytes]
            vlq_bytes_bits = [
                (
                    vlq_byte & 0x40,
                    vlq_byte & 0x20,
                    vlq_byte & 0x10,
                    vlq_byte & 0x8,
                    vlq_byte & 0x4,
                    vlq_byte & 0x2,
                    vlq_byte & 0x1,
                )
                for vlq_byte in vlq_bytes
            ]
            no_bits = len(vlq_bytes_bits) * 7
            no_bytes = 8 * math.ceil(no_bits / 8)
            node_value = 0
            for byte_idx, vlq_byte_bits in enumerate(
                reversed(vlq_bytes_bits)
            ):  # reversed i.e. bytes lsb first
                for bit_idx, vlq_byte_bit in enumerate(
                    reversed(vlq_byte_bits)
                ):  # reversed i.e. bits lsb first
                    node_value = (
                        node_value | (0x1 << (bit_idx + (byte_idx * 7)))
                        if vlq_byte_bit
                        else node_value
                    )
            nodes.append(node_value)
        else:
            nodes.append(first_byte)
            data = data[i + 1 :]
    return ".".join([str(node) for node in nodes])


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
