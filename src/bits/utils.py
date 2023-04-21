import hashlib
import typing

import bits.base58
import bits.ecmath
import bits.keys
import bits.pem
import bits.script.constants
from bits.bips import bip173


def pubkey(x: int, y: int, compressed=False) -> bytes:
    """
    Returns SEC1 pubkey from point (x, y)

    >>> pubkey(*(88828742484815144809405969644853584197652586004550817561544596238129398385750, 53299775652378523772666068229018059902560429447534834823349875811815397393717), compressed=True).hex()
    '03c463495bd336bc29636ed6d8c1cf162b45d76adda4df9499370dded242758c56'
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
    assert p > 0 and p < bits.ecmath.SECP256K1_N, f"private key not in range(1, N): {p}"
    return p


def compute_point(privkey_: bytes) -> typing.Tuple[int]:
    """
    Compute (x, y) public key point from private key

    >>> compute_point(bytes.fromhex('c3e7b149ad167dc83a5653a9eaae1cc50b36793bfdc050d8efab831d04b876a7'))
    (88828742484815144809405969644853584197652586004550817561544596238129398385750, 53299775652378523772666068229018059902560429447534834823349875811815397393717)
    """
    k = privkey_int(privkey_)
    return bits.ecmath.point_scalar_mul(
        k, (bits.ecmath.SECP256K1_Gx, bits.ecmath.SECP256K1_Gy)
    )


def point(pubkey_: bytes) -> typing.Tuple[int]:
    """
    Return (x, y) point from SEC1 public key

    >>> point(bytes.fromhex('03c463495bd336bc29636ed6d8c1cf162b45d76adda4df9499370dded242758c56'))
    (88828742484815144809405969644853584197652586004550817561544596238129398385750, 53299775652378523772666068229018059902560429447534834823349875811815397393717)
    """
    assert len(pubkey_) == 33 or len(pubkey_) == 65, "invalid pubkey length"
    version = pubkey_[0]
    payload = pubkey_[1:]
    x = int.from_bytes(payload[:32], "big")
    if version == 2:
        # compressed, y
        y = bits.ecmath.y_from_x(x)[0]
    elif version == 3:
        # compressed, -y
        y = bits.ecmath.y_from_x(x)[1]
    elif version == 4:
        # uncompressed
        y = int.from_bytes(payload[32:], "big")
    else:
        raise ValueError(f"unrecognized version: {version}")
    assert bits.ecmath.point_is_on_curve(x, y), "invalid pubkey"
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
    SHA256(witness_script)
    """
    return hashlib.sha256(witness_script).digest()


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


def parse_compact_size_uint(payload: bytes) -> typing.Tuple[int, bytes]:
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


def sha256(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


def hash256(msg: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def to_bitcoin_address(
    payload: bytes,
    addr_type: str = "p2pkh",
    network: str = "mainnet",
    witness_version: typing.Optional[int] = None,
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
        return bip173.segwit_addr(
            payload, witness_version=witness_version, network=network
        )
    assert addr_type in ["p2pkh", "p2sh"], f"unrecognized address type: {addr_type}"
    if network == "mainnet" and addr_type == "p2pkh":
        version = b"\x00"
    elif network in ["testnet", "regtest"] and addr_type == "p2pkh":
        version = b"\x6f"
    elif network == "mainnet" and addr_type == "p2sh":
        version = b"\x05"
    elif network in ["testnet", "regtest"] and addr_type == "p2sh":
        version = b"\xc4"
    return bits.base58.base58check(version + payload)


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
    parsed = bits.pem.parse_asn1(sig_)
    # r_val = int.from_bytes(parsed[0][2][0][2], "big")
    r_len = parsed[0][2][0][1]
    s_val = int.from_bytes(parsed[0][2][1][2], "big")
    s_len = parsed[0][2][1][1]
    if s_val > bits.ecmath.SECP256K1_N // 2 or s_val < 1:
        # s_val = SECP256K1_N - s_val
        s_val = bits.ecmath.sub_mod_p(0, s_val, p=bits.ecmath.SECP256K1_N)
        parsed[0][2][1][2] = s_val.to_bytes(32, "big")
        parsed[0][2][1][1] = 32
        parsed[0][1] = 32 + r_len + 4
        encoded = bits.pem.encode_parsed_asn1(parsed[0])
        return encoded
    return sig_


def pubkey_from_pem(pem_: bytes):
    decoded_key = pem_decode_key(pem_)
    if len(decoded_key) == 2:
        return decoded_key[1]
    return decoded_key


# influenced by electrum
# https://github.com/spesmilo/electrum/blob/4.4.0/electrum/bitcoin.py#L618-L625
WIF_NETWORK_BASE = {"mainnet": 0x80, "testnet": 0xEF, "regtest": 0xEF}
WIF_SCRIPT_OFFSET = {
    "p2pkh": 0,
    "p2wpkh": 1,
    "p2sh-p2wpkh": 2,
    "p2pk": 3,
    "multisig": 4,
    "p2sh": 5,
    "p2wsh": 6,
    "p2sh-p2wsh": 7,
}
WIF_TYPE_COMBINATIONS = {
    ("mainnet", "p2pkh"): 0x80,
    ("mainnet", "p2wpkh"): 0x81,
    ("mainnet", "p2sh-p2wpkh"): 0x82,
    ("mainnet", "p2pk"): 0x83,
    ("mainnet", "multisig"): 0x84,
    ("mainnet", "p2sh"): 0x85,
    ("mainnet", "p2wsh"): 0x86,
    ("mainnet", "p2sh-p2wsh"): 0x87,
    ("testnet", "p2pkh"): 0xEF,
    ("testnet", "p2wpkh"): 0xF0,
    ("testnet", "p2sh-p2wpkh"): 0xF1,
    ("testnet", "p2pk"): 0xF2,
    ("testnet", "multisig"): 0xF3,
    ("testnet", "p2sh"): 0xF4,
    ("testnet", "p2wsh"): 0xF5,
    ("testnet", "p2sh-p2wsh"): 0xF6,
}
WIF_TYPE_COMBINATIONS_MAP = {value: key for key, value in WIF_TYPE_COMBINATIONS.items()}


def wif_encode(
    privkey_: bytes,
    addr_type: str = "p2pkh",
    network: str = "mainnet",
    data: bytes = b"",
) -> bytes:
    """
    WIF encoding
    https://en.bitcoin.it/wiki/Wallet_import_format

    ** Extended WIF spec to include redeemscript or other script data
        at suffix

    Args:
        privkey_: bytes, private key
        addr_type: str, address type. choices => [
            "p2pkh",
            "p2wpkh",
            "p2sh-p2wpkh",
            "p2pk",
            "multisig",
            "p2sh",
            "p2wsh",
            "p2sh-p2wsh"
        ]
        network: str, e.g. mainnet, testnet, or regtest
        data: bytes, appended to key prior to base58check encoding.
            For p2(w)sh address types, supply redeem script.
            For p2pk(h) address types, use 0x01 to associate WIF key with a compressed
                pubkey, omit for uncompressed pubkey.
            For multsig, supply redeem script
            For p2wpkh & p2sh-p2wpkh, data shall be omitted since compressed pubkey
                (and redeem_script) are implied
            For p2sh-p2wsh, supply witness_script
    """
    privkey_int(privkey_)  # key validation
    prefix = (WIF_NETWORK_BASE[network] + WIF_SCRIPT_OFFSET[addr_type]).to_bytes(
        1, "big"
    )
    wif = prefix + privkey_
    if data:
        wif += data
    return bits.base58.base58check(wif)


def wif_decode(
    wif_: bytes, return_dict=False
) -> typing.Union[typing.Tuple[bytes, bytes, bytes], dict]:
    """
    Returns:
        version, key, data
    """
    decoded = bits.base58.base58check_decode(wif_)
    version = decoded[0:1]
    key_ = decoded[1:33]
    addtl_data = decoded[33:]
    network, addr_type = WIF_TYPE_COMBINATIONS_MAP[int.from_bytes(version, "big")]

    if return_dict:
        decoded = {
            "version": version.hex(),
            "network": network,
            "addr_type": addr_type,
            "key": key_.hex(),
            "data": addtl_data.hex(),
        }
        return decoded
    else:
        return version, key_, addtl_data


def pem_decode_key(pem_: bytes) -> typing.Union[tuple[bytes, bytes], tuple[bytes]]:
    """
    Decode from pem / der encoded EC private / public key
    Returns:
        (privkey, pubkey) or pubkey, respectively
    """
    decoded = bits.pem.decode_pem(pem_)
    parsed = bits.pem.parse_asn1(decoded)
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
        return bits.pem.encode_pem(
            bits.pem.encode_parsed_asn1(parsed_data_struct[0]),
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
        return bits.pem.encode_pem(
            bits.pem.encode_parsed_asn1(parsed_data_struct[0]),
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
    return bits.pem.encode_parsed_asn1(signature_asn1_data_struct[0])


def der_decode_sig(der: bytes) -> typing.Tuple[int, int]:
    parsed = bits.pem.parse_asn1(der)
    r = int.from_bytes(parsed[0][2][0][2], "big")
    s = int.from_bytes(parsed[0][2][1][2], "big")
    return r, s


def sig(
    key: bytes,
    msg: bytes,
    sighash_flag: typing.Optional[int] = None,
    msg_preimage: bool = False,
) -> bytes:
    """
    Create DER encoded Bitcoin signature from message, optional sighash_flag

    Sighash_flag gets appended to msg, this data is then hashed with HASH256,
        signed, and DER-encoded

    Args:
        key: bytes, private key
        msg: bytes,
        sighash_flag: Optional[int], appended to msg before HASH256
        msg_preimage: whether msg is pre-image or not
            pre-image already has 4 byte sighash flag appended
            if msg_preimage, msg is still hashed, and 1 byte sighash_flag still appended
            after signing/der-encoding
    Returns:
        bytes, signature(HASH256(msg + sighash_flag))
    """
    if not msg_preimage and sighash_flag is not None:
        msg += sighash_flag.to_bytes(4, "little")
    elif msg_preimage and sighash_flag is not None:
        sh_flag = int.from_bytes(msg[-4:], "little")
        assert (
            sh_flag == sighash_flag
        ), "sighash_flag parsed from msg preimage does not match provided sighash_flag argument"
    elif msg_preimage:
        sh_flag = int.from_bytes(msg[-4:], "little")
    sigdata = hash256(msg)
    r, s = bits.ecmath.sign(privkey_int(key), int.from_bytes(sigdata, "big"))
    signature_der = der_encode_sig(r, s)
    if sighash_flag is not None:
        signature_der += sighash_flag.to_bytes(1, "little")
    elif msg_preimage:
        # if msg_preimage=True (msg preimage contains sighash flag) and sighash_flag not provided as arg
        signature_der += sh_flag.to_bytes(1, "little")
    return signature_der


def sig_verify(
    sig_: bytes, pubkey_: bytes, msg: bytes, msg_preimage: bool = False
) -> str:
    sighash_flag = sig_[-1]
    r, s = der_decode_sig(sig_[:-1])
    if not msg_preimage:
        msg += sighash_flag.to_bytes(4, "little")
    msg_digest = hash256(msg)
    try:
        result = bits.ecmath.verify(
            r, s, point(pubkey_), int.from_bytes(msg_digest, "big")
        )
    except AssertionError as err:
        return err.args[0]
    return "OK"
