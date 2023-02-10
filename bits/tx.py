"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
from hashlib import sha256
from typing import List
from typing import Optional

import bits.script.constants
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
    coinbase_script: bytes,
    sequence: bytes = b"\xff\xff\xff\xff",
    block_height: Optional[int] = None,
) -> bytes:
    """
    Create coinbase txin
    Args:
        coinbase_script: bytes, arbitrary data not exceeding 100 bytes
        block_height: bytes, block height of this block in script language
            (now required per BIP34)

    """
    if block_height:
        # "minimally encoded serialized CScript"
        if block_height <= 16:
            op = getattr(bits.script.constants, f"OP_{block_height}")
            coinbase_script = op.to_bytes(1, "big") + coinbase_script
        else:
            # signed int
            number_of_bytes = (block_height.bit_length() + 8) // 8
            coinbase_script = (
                number_of_bytes.to_bytes(1, "little")
                + block_height.to_bytes(number_of_bytes, "little")
                + coinbase_script
            )
    if len(coinbase_script) > 100:
        raise ValueError("script exceeds 100 bytes!")
    return txin(
        outpoint(b"\x00" * 32, UINT32_MAX),  # null
        coinbase_script,
        sequence=sequence,
    )


def coinbase_tx(
    coinbase_script: bytes,
    script_pubkey: bytes,
    block_reward: Optional[int] = None,
    block_height: Optional[int] = None,
    network: str = "mainnet",
) -> bytes:
    if network == "mainnet" or network == "testnet":
        raise NotImplementedError
        if block_height:
            halvings = block_height // 2016
    elif network == "regtest":
        if block_height:
            max_reward = int(50e8)
            halvings = block_height // 150
            if halvings:
                max_reward //= 2 * halvings
            if block_reward:
                assert block_reward <= max_reward, "block reward too high"
            else:
                block_reward = max_reward
    else:
        raise ValueError("unrecognized network")
    return tx(
        [coinbase_txin(coinbase_script, block_height=block_height)],
        [txout(block_reward, script_pubkey)],
    )
