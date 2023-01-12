"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
from hashlib import sha256
from typing import List

from bits.utils import compact_size_uint
from bits.utils import d_hash


UINT32_MAX = 2**32 - 1


def outpoint(txid_: bytes, index: int) -> bytes:
    """
    # https://developer.bitcoin.org/reference/transactions.html#outpoint-the-specific-part-of-a-specific-output
    Args:
        txid_: bytes, txid in internal byte order
    """
    return txid_ + index.to_bytes(4, "little")


def txin(
    prev_outpoint: bytes,
    script_sig: bytes,
    sequence: bytes = b"\xff\xff\xff\xff",
) -> bytes:
    return prev_outpoint + compact_size_uint(len(script_sig)) + script_sig + sequence


def txout(value: int, script_pubkey: bytes) -> bytes:
    return (
        value.to_bytes(8, "little")
        + compact_size_uint(len(script_pubkey))
        + script_pubkey
    )


def tx(
    txins: List[bytes],
    txouts: List[bytes],
    version: int = 1,
    locktime: int = 0,
    script_witnesses: List[bytes] = [],
) -> bytes:
    """
    Transaction serialization, optional SegWit
    """
    if script_witnesses:
        marker = b"\x00"
        flag = b"\x01"
        return (
            version.to_bytes(4, "little")
            + marker
            + flag
            + compact_size_uint(len(txins))
            + b"".join(txins)
            + compact_size_uint(len(txouts))
            + b"".join(txouts)
            + b"".join(script_witnesses)
            + locktime.to_bytes(4, "little")
        )
    return (
        version.to_bytes(4, "little")
        + compact_size_uint(len(txins))
        + b"".join(txins)
        + compact_size_uint(len(txouts))
        + b"".join(txouts)
        + locktime.to_bytes(4, "little")
    )


def txid(tx_: bytes) -> str:
    return d_hash(tx_)[::-1].hex()  # rpc byte order


# SegWit
def wtxid(
    tx_: bytes, witness: bytes, marker: bytes = b"\x00", flag: bytes = b"\x01"
) -> bytes:
    # https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    # if all txins are non-witness program, wxtid == txid
    # returns:
    #   d_hash([nVersion][marker][flag][txins][txouts][witness][nLockTime])

    return


def coinbase_txin(
    coinbase_script: bytes, sequence: bytes = b"\xff\xff\xff\xff"
) -> bytes:
    """
    Create coinbase txin
    Args:
        coinbase_script: bytes, arbitrary data not exceeding 100 bytes
        block_height: bytes, block height of this block in script language
            (now required per BIP34)

    """
    if len(coinbase_script) > 100:
        raise ValueError("script exceeds 100 bytes!")
    return txin(
        outpoint(b"\x00" * 32, UINT32_MAX),  # null
        coinbase_script,
        sequence=sequence,
    )


def coinbase_tx(
    coinbase_script: bytes,
    block_reward: int,
    script_pubkey: bytes,
    # block_height: bytes = b"",
) -> bytes:
    return tx(
        [coinbase_txin(coinbase_script)],
        [txout(block_reward, script_pubkey)],
    )
