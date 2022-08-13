"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
from hashlib import sha256

from bits.btypes import compact_size_uint


def outpoint(txid: bytes, index: int) -> bytes:
    return txid + index.to_bytes(4, "little")


def txin(
    prev_outpoint: bytes, script_sig: bytes, sequence: bytes = b"\xff\xff\xff\xff"
) -> bytes:
    return prev_outpoint + compact_size_uint(len(script_sig)) + script_sig + sequence


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
