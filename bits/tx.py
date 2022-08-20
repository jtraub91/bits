"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
from hashlib import sha256

from bits.btypes import compact_size_uint
from bits.utils import d_hash


def outpoint(txid: bytes, index: int) -> bytes:
    return txid + index.to_bytes(4, "little")


def txin(
    prev_outpoint: bytes,
    script_sig: bytes,
    sequence: bytes = b"\xff\xff\xff\xff",
) -> bytes:
    return (
        prev_outpoint
        + compact_size_uint(len(script_sig))
        + script_sig
        + sequence
    )


def txout(value: int, script_pubkey: bytes) -> bytes:
    return (
        value.to_bytes(8, "little", signed=True)
        + compact_size_uint(len(script_pubkey))
        + script_pubkey
    )


def tx(txins: list[bytes], txouts: list[bytes], locktime: int = 0) -> bytes:
    version = 1
    return (
        version.to_bytes(4, "little", signed=True)
        + compact_size_uint(len(inputs))
        + b"".join(txins)
        + compact_size_uint(len(outputs))
        + b"".join(txouts)
        + locktime.to_bytes(4, "little")
    )


def txid(tx_: bytes) -> bytes:
    return d_hash(tx_)


# SegWit
def wtxid(
    tx_: bytes, witness: bytes, marker: bytes = b"\x00", flag: bytes = b"\x01"
) -> bytes:
    # https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    # if all txins are non-witness program, wxtid == txid
    # returns:
    #   d_hash([nVersion][marker][flag][txins][txouts][witness][nLockTime])

    return
