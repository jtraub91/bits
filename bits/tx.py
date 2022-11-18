"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
from hashlib import sha256

from bits.utils import compact_size_uint
from bits.utils import d_hash


UINT32_MAX = 2**32 - 1


def outpoint(txid: bytes, index: int) -> bytes:
    return txid + index.to_bytes(4, "little")


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
    txins: list[bytes], txouts: list[bytes], version: int = 1, locktime: int = 0
) -> bytes:
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
    block_height: bytes = b"",
) -> bytes:
    return tx(
        [coinbase_txin(coinbase_script, block_height=block_height)],
        [txout(block_reward, script_pubkey)],
    )
