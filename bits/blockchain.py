"""
blockchain lulz
"""
import os
from typing import List
from typing import Tuple

from bits.script.utils import p2pk_script_pubkey
from bits.tx import coinbase_txin
from bits.tx import tx
from bits.tx import txout
from bits.utils import compact_size_uint
from bits.utils import d_hash


COIN = 100000000  # satoshis / bitcoin
NULL_32 = b"\x00" * 32

MAX_BLOCKFILE_SIZE = 0x08000000

# https://en.bitcoin.it/wiki/Target
# https://developer.bitcoin.org/reference/block_chain.html#target-nbits
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
MAX_TARGET_REGTEST = 0x7FFFFF0000000000000000000000000000000000000000000000000000000000
# https://en.bitcoin.it/wiki/Difficulty


def target_threshold(nBits: bytes) -> int:
    """
    Calculate target threshold from compact nBits
    # https://developer.bitcoin.org/reference/block_chain.html#target-nbits
    Args:
        nBits: bytes, rpc byte order
    >>> target = target_threshold(bytes.fromhex("207fffff"))
    >>> hex(target)
    '0x7fffff0000000000000000000000000000000000000000000000000000000000'
    """
    mantissa = nBits[-3:]
    exponent = int.from_bytes(nBits[:-3], "big")
    target = int.from_bytes(mantissa, "big") * 256 ** (exponent - len(mantissa))
    return target


def difficulty(target: int, network: str = "mainnet") -> float:
    """
    difficulty = difficulty_1_target / current_target
    https://en.bitcoin.it/wiki/Difficulty

    """
    if network == "mainnet" or network == "testnet":
        return MAX_TARGET / target
    elif network == "regtest":
        return MAX_TARGET_REGTEST / target
    else:
        raise ValueError("unrecognized network")


def block_header(
    version: int,
    prev_blockheaderhash: bytes,
    merkle_root_hash: bytes,
    ntime: int,
    nBits: bytes,
    nNonce: int,
) -> bytes:
    """ """
    # https://developer.bitcoin.org/reference/block_chain.html#block-headers
    return (
        version.to_bytes(4, "little")
        + prev_blockheaderhash
        + merkle_root_hash
        + ntime.to_bytes(4, "little")
        + nBits
        + nNonce.to_bytes(4, "little")
    )


def merkle_root(txns: List[bytes]) -> bytes:
    """
    merkle root from a list of transactions
    https://developer.bitcoin.org/reference/block_chain.html#merkle-trees
    """
    row = txns
    while len(row) > 1:
        odd = len(row) % 2
        if odd:
            row += [row[-1]]
        branches = []
        for i in len(row) // 2:
            branches += d_hash(row[2 * i] + row[2 * i + 1])
        row = branches
    return d_hash(row[0])


def genesis_coinbase_tx():
    # https://github.com/bitcoin/bitcoin/blob/v0.1.5/main.cpp#L1490
    # https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L54
    satoshis_pk = bytes.fromhex(
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    )
    psz_timestamp = (
        b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    )
    # https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L25
    # https://github.com/bitcoin/bitcoin/blob/v0.1.5/main.cpp#L1488
    coinbase_script = (
        b"\x04"  # OP_PUSH_4
        + (486604799).to_bytes(4, "little")
        + b"\x01"  # OP_PUSH_1
        + (4).to_bytes(1, "little")
        + len(psz_timestamp).to_bytes(1, "little")  # OP_PUSH_69
        + psz_timestamp
    )
    coinbase_tx = tx(
        [coinbase_txin(coinbase_script)],
        [txout(50 * COIN, p2pk_script_pubkey(satoshis_pk))],
    )
    return coinbase_tx


def genesis_block():
    # https://github.com/bitcoin/bitcoin/blob/v0.1.5/main.cpp#L1495-L1498
    version: int = 1
    nTime = 1231006505
    nBits = 0x1D00FFFF
    nNonce = 2083236893

    coinbase_tx = genesis_coinbase_tx()
    merkle_ = merkle_root([coinbase_tx])

    return block_ser(
        block_header(1, NULL_32, merkle_, nTime, nBits, nNonce), [coinbase_tx]
    )


def block_ser(blk_hdr: bytes, txns: List[bytes]) -> bytes:
    return blk_hdr + compact_size_uint(len(txns)) + b"".join(txns)


def block_deser(block: bytes) -> Tuple[bytes, List[bytes]]:
    # return block_header_, txns
    raise NotImplementedError
