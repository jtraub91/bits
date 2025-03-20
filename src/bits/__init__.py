__version__ = "0.2.2"

import hashlib
import json
import logging
import os
import sys
import typing

import bits.base58
import bits.crypto
import bits.ecmath
import bits.keys
import bits.script.constants
from bits.bips import bip173
from bits.bips.bip350 import BECH32M_CONST

logging.TRACE = logging.DEBUG - 1
logging.addLevelName(logging.TRACE, "TRACE")


class Logger(logging.getLoggerClass()):
    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(logging.TRACE):
            self._log(logging.TRACE, msg, args, **kwargs)


logging.setLoggerClass(Logger)


def init_logging(log_level: str):
    """
    Initialize logging with a StreamHandler set to log_level
    Args:
        log_level: str, log level
    """
    log = logging.getLogger(__name__)
    log.setLevel(logging.TRACE)  # set root logger to lowest level
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    sh.setLevel(getattr(logging, log_level.upper()))
    log.addHandler(sh)
    return log


def read_bytes(
    file_: typing.Optional[typing.IO] = None, input_format: str = "raw"
) -> bytes:
    """
    Read from optional file or stdin and convert to bytes

    Any newlines will be stripped from beginning / end for hex and bin, only.
    Raw is read without any additional processing.

    Furthermore, hex and bin will be left-zero-padded to the nearest byte, if they are
    not provided in 8-bit multiples.

    Args:
        file_: Optional[IO], optional file object - otherwise stdin is used
        input_format: str, "raw", "hex", or "bin"
    Returns:
        data as bytes
    """
    if input_format == "raw":
        data = file_.buffer.read() if file_ else sys.stdin.buffer.read()
    elif input_format == "hex":
        data = file_.read().strip() if file_ else sys.stdin.read().strip()
        if len(data) % 2:
            data = "0" + data
        data = bytes.fromhex(data)
    elif input_format == "bin":
        data = file_.read().strip() if file_ else sys.stdin.read().strip()
        if len(data) % 8:
            data = "0" * (8 - len(data) % 8) + data
        data = int(data, 2).to_bytes(len(data) // 8, "big")
    else:
        raise ValueError(f"unrecognized input format: {input_format}")
    return data


def write_bytes(
    data: bytes,
    file_: typing.Optional[typing.IO] = None,
    output_format: str = "raw",
):
    """
    Write bytes to file_ or stdout. bin/hex output format will have newline appended
    Args:
        data: bytes, bytes to print
        file_: Optional[IO], file object to write to, if None uses stdout
        output_format: str, 'raw', 'bin', or 'hex'
    """
    if not data:
        return
    if output_format == "raw":
        if file_ is not None:
            file_.buffer.write(data)
        else:
            sys.stdout.buffer.write(data)
    elif output_format == "bin" or output_format == "hex":
        format_spec = (
            f"0{len(data) * 2}x" if output_format == "hex" else f"0{len(data) * 8}b"
        )
        formatted_data = format(int.from_bytes(data, "big"), format_spec)
        formatted_data += os.linesep
        if file_ is not None:
            file_.write(formatted_data)
        else:
            sys.stdout.write(formatted_data)
    else:
        raise ValueError(f"unrecognized output format: {output_format}")


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
        return pubkey(*bits.ecmath.point(pubkey_), compressed=True)
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


def segwit_addr(
    data: bytes, witness_version: int = 0, network: str = "mainnet"
) -> bytes:
    """
    Defined per BIP173 bech32
    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format
    and bech32m per BIP350
    https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    """
    if network == "mainnet":
        hrp = b"bc"
    elif network == "testnet":
        hrp = b"tb"
    elif network == "regtest":
        hrp = b"bcrt"
    else:
        raise ValueError(f"unrecognized network: {network}")
    assert witness_version in range(17), "witness version not in [0, 16]"
    if witness_version == 0:
        bech32_constant = 1
    else:
        # witness version 1 thru 16
        bech32_constant = BECH32M_CONST
    return bip173.bech32_encode(
        hrp,
        data,
        witness_version=bip173.bech32_chars[witness_version : witness_version + 1],
        constant=bech32_constant,
    )


def decode_segwit_addr(
    addr: bytes, __support_bip350: bool = True
) -> typing.Tuple[bytes, int, bytes]:
    """
    Decode SegWit address. See BIP173 and BIP350
    """
    hrp, data = bip173.parse_bech32(addr)
    assert data[:-6], "empty data"  # ignore checksum
    bech32_constant = 1
    if bip173.bech32_int_map[data[0:1]] != 0 and __support_bip350:
        bech32_constant = BECH32M_CONST
    bip173.assert_valid_bech32(hrp, data, constant=bech32_constant)
    witness_version = bip173.bech32_int_map[data[0:1]]
    assert witness_version in range(17), "witness version not in [0, 16]"
    data = data[1:-6]  # discard version byte and checksum
    witness_program = bip173.bech32_decode(data)
    return hrp, witness_version, witness_program


def assert_valid_segwit(
    hrp: bytes, witness_version: int, witness_program: bytes
) -> bool:
    """
    Assert valid SegWit address per BIP173
    """
    assert hrp in [b"bc", b"tb", b"bcrt"], "Invalid human-readable part"
    assert len(witness_program) in range(2, 41), "witness program length not in [2, 40]"
    if witness_version == 0:
        assert len(witness_program) in [
            20,
            32,
        ], "length of v0 witness program not 20 or 32"


def is_segwit_addr(addr_: bytes) -> bool:
    """
    Alterative to assert_valid_segwit that catches potential error
    Returns:
        bool, True if valid segwit address else False
    """
    try:
        hrp, witness_version, witness_program = decode_segwit_addr(addr_)
        assert_valid_segwit(hrp, witness_version, witness_program)
        return True
    except AssertionError as err:
        return False


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
    else:
        raise ValueError(
            f"version could not be set for combination of network ({network}) and addr_type ({addr_type}) provided"
        )
    return bits.base58.base58check(version + payload)


def is_addr(addr_: bytes) -> bool:
    if bits.base58.is_base58check(addr_):
        return True
    elif is_segwit_addr(addr_):
        return True
    return False


def assert_addr(addr_: bytes) -> bool:
    errors = []
    try:
        bits.base58.base58check_decode(addr_)
        return True
    except Exception as b58_err:
        errors.append(b58_err)
    try:
        hrp, witness_version, witness_program = decode_segwit_addr(addr_)
        assert_valid_segwit(hrp, witness_version, witness_program)
        return True
    except AssertionError as segwit_err:
        errors.append(segwit_err)
    raise AssertionError(
        "addr not identified as base58check nor segwit. "
        + f"Caught errors '{errors[0].args[0]}', '{errors[1].args[0]}', respectively"
    )


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
    bits.ecmath.privkey_int(privkey_)  # key validation
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


class Bytes(bytes):
    def __new__(cls, data, **kwargs):
        _deserializer_fun = getattr(cls, "_deserializer_fun", None)
        _serializer_fun = getattr(cls, "_serializer_fun", None)
        if isinstance(data, dict):
            bytes_data = _serializer_fun(**data)
            obj = super().__new__(cls, bytes_data, **kwargs)
            obj._dict = data
        else:
            obj = super().__new__(cls, data, **kwargs)
            obj._dict = getattr(cls, "_dict", None)
        obj._deserializer_fun = _deserializer_fun
        obj._serializer_fun = _serializer_fun
        return obj

    def __getitem__(self, key: str):
        if isinstance(key, (int, slice)):  # normal bytes behavior
            return super().__getitem__(key)
        return self.dict()[key]

    def __getattr__(self, attr: str):
        try:
            self.dict()[attr]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{attr}'"
            )

    def bin(self) -> str:
        if bytes(self) == b"":
            return ""
        return format(int.from_bytes(self, "big"), f"0{len(self) * 8}b")

    def dict(self, refresh: bool = False) -> dict:
        if self._dict is None or refresh:
            if self._deserializer_fun is None:
                raise RuntimeError(
                    "Cannot deserialize. _deserializer_fun is not defined"
                )
            self._dict = self._deserializer_fun(self)
        return self._dict

    def json(self, indent: int = None) -> str:
        return json.dumps(self.dict(), indent=indent)
