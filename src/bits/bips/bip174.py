"""
https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

<psbt> := <magic> <global-map> <input-map>* <output-map>*
<magic> := 0x70 0x73 0x62 0x74 0xFF
<global-map> := <keypair>* 0x00
<input-map> := <keypair>* 0x00
<output-map> := <keypair>* 0x00
<keypair> := <key> <value>
<key> := <keylen> <keytype> <keydata>
<value> := <valuelen> <valuedata>
"""
import base64
from typing import Optional

from bits import compact_size_uint
from bits import parse_compact_size_uint

# constants defined per BIP0174 and seen in
# https://github.com/bitcoin/bitcoin/blob/v28.0/src/psbt.h#L24-L66

# magic bytes
PSBT_MAGIC_BYTES = b"psbt\xff"

# global types
PSBT_GLOBAL_UNSIGNED_TX = b"\x00"
PSBT_GLOBAL_XPUB = b"\x01"
PSBT_GLOBAL_VERSION = b"\xFB"
PSBT_GLOBAL_PROPRIETARY = b"\xFC"

# input types
PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIGHASH = b"\x03"
PSBT_IN_REDEEMSCRIPT = b"\x04"
PSBT_IN_WITNESSSCRIPT = b"\x05"
PSBT_IN_BIP32_DERIVATION = b"\x06"
PSBT_IN_SCRIPTSIG = b"\x07"
PSBT_IN_SCRIPTWITNESS = b"\x08"
PSBT_IN_RIPEMD160 = b"\x0A"
PSBT_IN_SHA256 = b"\x0B"
PSBT_IN_HASH160 = b"\x0C"
PSBT_IN_HASH256 = b"\x0D"
PSBT_IN_TAP_KEY_SIG = b"\x13"
PSBT_IN_TAP_SCRIPT_SIG = b"\x14"
PSBT_IN_TAP_LEAF_SCRIPT = b"\x15"
PSBT_IN_TAP_BIP32_DERIVATION = b"\x16"
PSBT_IN_TAP_INTERNAL_KEY = b"\x17"
PSBT_IN_TAP_MERKLE_ROOT = b"\x18"
PSBT_IN_PROPRIETARY = b"\xFC"

# output types
PSBT_OUT_REDEEMSCRIPT = b"\x00"
PSBT_OUT_WITNESSSCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
PSBT_OUT_TAP_INTERNAL_KEY = b"\x05"
PSBT_OUT_TAP_TREE = b"\x06"
PSBT_OUT_TAP_BIP32_DERIVATION = b"\x07"
PSBT_OUT_PROPRIETARY = b"\xFC"

# separator
PSBT_SEPARATOR = b"\x00"


def keypair(keytype: bytes, keydata: bytes = b"", valuedata: bytes = b"") -> bytes:
    keylen = compact_size_uint(len(keytype + keydata))
    key = keylen + keytype + keydata
    valuelen = compact_size_uint(len(valuedata))
    value = valuelen + valuedata
    return key + value


def parse_psbt(psbt_: bytes, b64decode=False):
    """
    Args:
        psbt_: bytes, PSBT
        b64decode: bool, base64 decode PSBT if True
    """
    if b64decode:
        psbt_ = base64.b64decode(psbt_)
    magic = psbt_[:5]
    assert magic == PSBT_MAGIC_BYTES, "magic mismatch, invalid PSBT"
    psbt_ = psbt_[5:]

    global_map = []
    while not psbt_[0] == 0:
        keylen, psbt_ = parse_compact_size_uint(psbt_)
        keytype = psbt_[0]
        keydata = psbt_[1:keylen]
        psbt_ = psbt_[keylen:]
        valuelen, psbt_ = parse_compact_size_uint(psbt_)
        valuedata = psbt_[:valuelen]
        psbt_ = psbt_[valuelen:]
        global_map.append(
            {"keytype": keytype, "keydata": keydata.hex(), "valuedata": valuedata.hex()}
        )

    input_map = []
    while not psbt_[0] == 0:
        keylen, psbt_ = parse_compact_size_uint(psbt_)
        keytype = psbt_[0]
        keydata = psbt_[1:keylen]
        psbt_ = psbt_[keylen:]
        valuelen, psbt_ = parse_compact_size_uint(psbt_)
        valuedata = psbt_[:valuelen]
        psbt_ = psbt_[valuelen:]
        input_map.append(
            {"keytype": keytype, "keydata": keydata.hex(), "valuedata": valuedata.hex()}
        )

    output_map = []
    while not psbt_[0] == 0:
        keylen, psbt_ = parse_compact_size_uint(psbt_)
        keytype = psbt_[0]
        keydata = psbt_[1:keylen]
        psbt_ = psbt_[keylen:]
        valuelen, psbt_ = parse_compact_size_uint(psbt_)
        valuedata = psbt_[:valuelen]
        psbt_ = psbt_[valuelen:]
        output_map.append(
            {"keytype": keytype, "keydata": keydata.hex(), "valuedata": valuedata.hex()}
        )

    return {
        "psbt_version": 0,
        "global_map": global_map,
        "input_map": input_map,
        "output_map": output_map,
    }
