import hashlib
import math
import os
import re
import stat
import time
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import bits.script.constants
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
from bits.pem import decode_pem
from bits.pem import encode_parsed_asn1
from bits.pem import encode_pem
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
    assert len(pubkey_) == 33 or len(pubkey_) == 65, "invalid pubkey length"
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


def is_point(pubkey_: bytes):
    try:
        point(pubkey_)
        return True
    except AssertionError:
        return False


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
    return hashlib.new("ripemd160", hashlib.sha256(pubkey_).digest()).digest()


def script_hash(redeem_script: bytes) -> bytes:
    """
    HASH160(redeem_script)
    """
    return hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()


def witness_script_hash(witness_script: bytes) -> bytes:
    """
    HASH256(witness_script)
    """
    return hashlib.sha256(hashlib.sha256(witness_script).digest()).digest()


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


def hash160(msg: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(msg).digest()).digest()


def ripemd160(msg: bytes) -> bytes:
    return hashlib.new("ripemd160", msg).digest()


def s_hash(msg: bytes) -> bytes:
    """
    Single sha256 hash of msg
    """
    return hashlib.sha256(msg).digest()


def sha256(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


def d_hash(msg: bytes) -> bytes:
    """
    Double sha256 hash of msg
    """
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def hash256(msg: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def to_bitcoin_address(
    payload: bytes,
    addr_type: str = "p2pkh",
    network: str = "mainnet",
    witness_version: Optional[int] = None,
) -> bytes:
    """
    Encode payload as bitcoin address invoice (optional segwit)
    Args:
        payload: bytes, pubkey_hash or script_hash
        addr_type: str, address type, "p2pkh" or "p2sh".
            results in p2wpkh or p2wsh, respectively when combined with witness_version
        network: str, mainnet, testnet, or regtest
        witness_version: Optional[int], witness version for native segwit addresses
            usage implies p2wpkh or p2wsh, accordingly
    Returns:
        base58 (or bech32 segwit) encoded bitcoin address
    """
    assert network in [
        "mainnet",
        "testnet",
        "regtest",
    ], f"unrecognized network: {network}"
    if witness_version is not None:
        assert witness_version in range(17), "witness version not in [0, 16]"
        return segwit_addr(payload, witness_version=witness_version, network=network)
    assert addr_type in ["p2pkh", "p2sh"], f"unrecognized address type: {addr_type}"
    if network == "mainnet" and addr_type == "p2pkh":
        version = b"\x00"
    elif network in ["testnet", "regtest"] and addr_type == "p2pkh":
        version = b"\x6f"
    elif network == "mainnet" and addr_type == "p2sh":
        version = b"\x05"
    elif network in ["testnet", "regtest"] and addr_type == "p2sh":
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
    decoded_key = pem_decode_key(pem_)
    if len(decoded_key) == 2:
        return decoded_key[1]
    return decoded_key


WIF_NETWORK_BASE = {"mainnet": 0x80, "testnet": 0xEF, "regtest": 0xEF}
WIF_SCRIPT_OFFSET = {
    "p2pkh": 0,
    "p2wpkh": 1,
    "p2sh-p2wpkh": 2,
    "p2sh": 5,
    "p2wsh": 6,
    "p2sh-p2wsh": 7,
}
WIF_TYPE_COMBINATIONS = {
    ("mainnet", "p2pkh"): 0x80,
    ("mainnet", "p2wpkh"): 0x81,
    ("mainnet", "p2sh-p2wpkh"): 0x82,
    ("mainnet", "p2sh"): 0x85,
    ("mainnet", "p2wsh"): 0x86,
    ("mainnet", "p2sh-p2wsh"): 0x87,
    ("testnet", "p2pkh"): 0xEF,
    ("testnet", "p2wpkh"): 0xF0,
    ("testnet", "p2sh-p2wpkh"): 0xF1,
    ("testnet", "p2sh"): 0xF4,
    ("testnet", "p2wsh"): 0xF5,
    ("testnet", "p2sh-p2wsh"): 0xF6,
}
WIF_TYPE_COMBINATIONS_MAP = {value: key for key, value in WIF_TYPE_COMBINATIONS.items()}


def wif_encode(
    privkey_: bytes,
    addr_type: str = "p2pkh",
    network: str = "mainnet",
    compressed_pubkey: bool = True,
    redeem_script: bytes = b"",
) -> bytes:
    """
    WIF encoding
    # https://en.bitcoin.it/wiki/Wallet_import_format
    # https://river.com/learn/terms/w/wallet-import-format-wif/

    ** Extends electrum WIF spec to include redeemscript or other script data
        at suffix

    Args:
        privkey_: bytes, private key
        compressed_pubkey: bool, corresponds to a compressed pubkey
        network: str, mainnet or testnet
    """
    if len(privkey_) != 32:
        raise ValueError("private key length not 32 bytes")
    prefix = (WIF_NETWORK_BASE[network] + WIF_SCRIPT_OFFSET[addr_type]).to_bytes(
        1, "big"
    )
    wif = prefix + privkey_
    if compressed_pubkey:
        wif += b"\x01"
    elif redeem_script:
        wif += redeem_script
    return base58check(wif)


def wif_decode(wif_: bytes) -> Tuple[bytes, bytes, bool]:
    """
    Returns:
        version, key, compressed
    """
    decoded = base58check_decode(wif_)
    version = decoded[0]

    key_ = decoded[1:33]
    addtl_data = decoded[33:]

    compressed = False
    assert len(key_) == 32 or len(key_) == 33
    if len(key_) == 33:
        assert key_[-1:] == b"\x01"
        compressed = True
    return version, key_[:32], compressed


def pem_decode_key(pem_: bytes) -> Union[tuple[bytes, bytes], tuple[bytes]]:
    """
    Decode from pem / der encoded EC private / public key
    Returns:
        (privkey, pubkey) or pubkey, respectively
    """
    decoded = decode_pem(pem_)
    parsed = parse_asn1(decoded)
    if parsed[0][2][0][2] == b"\x01":
        return parsed[0][2][1][2], parsed[0][2][3][2][0][2][1:]
    elif parsed[0][2][0][2][0][2] == "id-ecPublicKey":
        return (parsed[0][2][1][2][1:],)
    else:
        raise ValueError("could not identify data as private nor public key")


def pem_encode_key(key_: bytes) -> bytes:
    """
    Encode (pub)key as pem
    """
    if len(key_) == 32:
        # private secp256k1 key
        parsed_data_struct = [
            [
                ["SEQUENCE (OF)", "Constructed", "Universal"],
                116,
                [
                    [["INTEGER", "Primitive", "Universal"], 1, b"\x01"],
                    [
                        ["OCTET STRING", "Primitive", "Universal"],
                        32,
                        key_,
                    ],
                    [
                        [0, "Constructed", "Context-specific"],
                        7,
                        [
                            [
                                ["OBJECT IDENTIFIER", "Primitive", "Universal"],
                                5,
                                "id-ansip256k1",
                            ]
                        ],
                    ],
                    [
                        [1, "Constructed", "Context-specific"],
                        68,
                        [
                            [
                                ["BIT STRING", "Primitive", "Universal"],
                                66,
                                b"\x00" + pubkey(*compute_point(key_)),
                            ]
                        ],
                    ],
                ],
            ]
        ]
        return encode_pem(
            encode_parsed_asn1(parsed_data_struct[0]),
            header=b"-----BEGIN EC PRIVATE KEY-----",
            footer=b"-----END EC PRIVATE KEY-----",
        )
    elif len(key_) == 33 or len(key_) == 65:
        parsed_data_struct = [
            [
                ["SEQUENCE (OF)", "Constructed", "Universal"],
                86 if len(key_) == 65 else 54,
                [
                    [
                        ["SEQUENCE (OF)", "Constructed", "Universal"],
                        16,
                        [
                            [
                                ["OBJECT IDENTIFIER", "Primitive", "Universal"],
                                7,
                                "id-ecPublicKey",
                            ],
                            [
                                ["OBJECT IDENTIFIER", "Primitive", "Universal"],
                                5,
                                "id-ansip256k1",
                            ],
                        ],
                    ],
                    [
                        ["BIT STRING", "Primitive", "Universal"],
                        66 if len(key_) == 65 else 34,
                        b"\x00" + key_,
                    ],
                ],
            ]
        ]
        return encode_pem(
            encode_parsed_asn1(parsed_data_struct[0]),
            header=b"-----BEGIN PUBLIC KEY-----",
            footer=b"-----END PUBLIC KEY-----",
        )
    else:
        raise ValueError(
            "key (based on len) not recognized as public nor private key data"
        )


def der_encode_sig(r: int, s: int) -> bytes:
    # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#der-encoding
    r_number_of_bytes = (r.bit_length() + 7) // 8
    r_bytes = r.to_bytes(r_number_of_bytes, "big")
    if r_bytes[0] >= 0x80:
        r_bytes = b"\x00" + r_bytes

    s_number_of_bytes = (s.bit_length() + 7) // 8
    s_bytes = s.to_bytes(s_number_of_bytes, "big")
    if s_bytes[0] >= 0x80:
        s_bytes += b"\x00" + s_bytes

    signature_asn1_data_struct = [
        [
            ["SEQUENCE (OF)", "Constructed", "Universal"],
            len(r_bytes) + len(s_bytes) + 4,
            [
                [
                    ["INTEGER", "Primitive", "Universal"],
                    len(r_bytes),
                    r_bytes,
                ],
                [
                    ["INTEGER", "Primitive", "Universal"],
                    len(s_bytes),
                    s_bytes,
                ],
            ],
        ]
    ]
    return encode_parsed_asn1(signature_asn1_data_struct[0])


def der_decode_sig(der: bytes) -> Tuple[int, int]:
    parsed = parse_asn1(der)
    r = int.from_bytes(parsed[0][2][0][2], "big")
    s = int.from_bytes(parsed[0][2][1][2], "big")
    return r, s


def openssl_sig(
    key: bytes, msg: bytes, sighash_flag: int = bits.script.constants.SIGHASH_ALL
):
    """
    Create signature
    Args:
        sigdata: bytes, data to sign
        key: bytes, signing key
        sighash_flag: int, SIGHASH flag to append to sigdata
    Returns:
        signature
    """
    # TODO: overcome possibility for overwritten files
    #  take hash of key / compute pubkey, is that secure?
    timestamp = int(time.time() * 1e9)
    key_filename = f".bits/tmp/key_{timestamp}.pem"
    with open(key_filename, "wb") as key_file:
        key_file.write(pem_encode_key(key))
    os.chmod(key_filename, stat.S_IREAD)
    sigdata = s_hash(msg + sighash_flag.to_bytes(4, "little"))
    sig = bits.openssl.sign(key_filename, stdin=sigdata)
    os.remove(key_filename)
    sig = ensure_sig_low_s(sig)
    return sig + sighash_flag.to_bytes(1, "little")


def sig(
    key: bytes,
    msg: bytes,
    sighash_flag: Optional[int] = None,
) -> bytes:
    if sighash_flag is not None:
        msg += sighash_flag.to_bytes(4, "little")
    sigdata = hash256(msg)
    r, s = bits.ecmath.sign(privkey_int(key), int.from_bytes(sigdata, "big"))
    signature_der = der_encode_sig(r, s)
    if sighash_flag is not None:
        signature_der += sighash_flag.to_bytes(1, "little")
    return signature_der


def sig_verify(
    sig_: bytes,
    pubkey_: bytes,
    msg: bytes,
) -> str:
    sighash_flag = sig_[-1]
    r, s = der_decode_sig(sig_[:-1])
    msg_digest = hash256(msg + sighash_flag.to_bytes(4, "little"))
    try:
        result = bits.ecmath.verify(
            r, s, point(pubkey_), int.from_bytes(msg_digest, "big")
        )
    except AssertionError as err:
        return err.args[0]
    return "OK"
