"""
blockchain lulz :P
"""
import os
import typing

import bits.script
import bits.tx


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
    """
    Create serialized block header from args

    # https://developer.bitcoin.org/reference/block_chain.html#block-headers

    Args:
        version: int, block version
        prev_blockheaderhash: bytes, hash of previous block header
        merkle_root_hash: bytes, merkle root hash
        ntime: int, Unix epoch time
        nBits: int, nBits encoding of target threshold
        nNonce: int, arbitrary number
    Returns:
        block header

    >>> merkle_root_hash = bytes.fromhex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
    >>> nBits = (0x1D00FFFF).to_bytes(4, "little")
    >>> bits.hash256(block_header(1, NULL_32, merkle_root_hash, 1231006505, nBits, 2083236893)).hex()
    '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'
    """
    return (
        version.to_bytes(4, "little")
        + prev_blockheaderhash
        + merkle_root_hash
        + ntime.to_bytes(4, "little")
        + nBits
        + nNonce.to_bytes(4, "little")
    )


def merkle_root(txns: typing.List[bytes]) -> bytes:
    """
    merkle root from a list of transactions
    https://developer.bitcoin.org/reference/block_chain.html#merkle-trees
    """
    row = [bits.hash256(txn) for txn in txns]
    if len(row) == 1:
        return row[0]
    elif len(row) % 2:
        row += [row[-1]]
    while len(row) >= 2:
        branches = []
        for i in range(0, len(row), 2):
            branches.append(bits.hash256(row[i] + row[i + 1]))
        row = branches
    return row[0]


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
    coinbase_tx = bits.tx.tx(
        [bits.tx.coinbase_txin(coinbase_script)],
        [bits.tx.txout(50 * COIN, bits.script.p2pk_script_pubkey(satoshis_pk))],
    )
    return coinbase_tx


def genesis_block():
    """
    Hard coded genesis block - mainnet
    >>> gb = genesis_block()
    >>> header = gb[:80]
    >>> import hashlib
    >>> hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    """
    # https://github.com/bitcoin/bitcoin/blob/v0.1.5/main.cpp#L1495-L1498
    version: int = 1
    nTime = 1231006505
    nBits = 0x1D00FFFF
    nNonce = 2083236893

    coinbase_tx = genesis_coinbase_tx()
    merkle_ = merkle_root([coinbase_tx])
    return block_ser(
        block_header(1, NULL_32, merkle_, nTime, nBits.to_bytes(4, "little"), nNonce),
        [coinbase_tx],
    )


def block_ser(blk_hdr: bytes, txns: typing.List[bytes]) -> bytes:
    return blk_hdr + bits.compact_size_uint(len(txns)) + b"".join(txns)


def block_deser(block: bytes) -> typing.Tuple[bytes, typing.List[dict]]:
    header = block[:80]
    number_of_txns, block_prime = bits.parse_compact_size_uint(block[80:])
    txns = []
    while block_prime:
        deserialized_tx, block_prime = bits.tx.tx_deser(block_prime)
        txns.append(deserialized_tx)
    assert (
        len(txns) == number_of_txns
    ), "error during parsing - number of txns does not match"
    return header, txns
