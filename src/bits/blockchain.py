"""
blockchain lulz :P
"""
import copy
import os
import typing

import bits.crypto
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
        nBits: bytes, internal byte order
    >>> target = target_threshold(bytes.fromhex("207fffff")[::-1])
    >>> hex(target)
    '0x7fffff0000000000000000000000000000000000000000000000000000000000'
    """
    mantissa = nBits[:3]
    exponent = int.from_bytes(nBits[3:], "little")
    target = int.from_bytes(mantissa, "little") * 256 ** (exponent - len(mantissa))
    return target


def n_bits(target: int) -> bytes:
    """
    Convert target threshold to nBits compact representation
    Args:
        target: int, target threshold
    >>> n_bits(0x7fffff0000000000000000000000000000000000000000000000000000000000)[::-1].hex()
    '207fffff'
    """
    target_bytes = target.to_bytes(32, "big")
    bytes_shifted = 0
    while target_bytes[0] == 0:
        target <<= 8
        target_bytes = target.to_bytes(32, "big")
        bytes_shifted += 1
    target >>= 29 * 8  # shift right 29 bytes to truncate
    mantissa = target.to_bytes(3, "little")
    exponent = (32 - bytes_shifted).to_bytes(1, "little")
    return mantissa + exponent


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
    >>> bits.crypto.hash256(block_header(1, NULL_32, merkle_root_hash, 1231006505, nBits, 2083236893)).hex()
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
    merkle root from a list of transaction ids
    https://developer.bitcoin.org/reference/block_chain.html#merkle-trees

    Args:
        txns: list[bytes], list of txids

    >>> # genesis block 0
    >>> txn_ids = ["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"]
    >>> txn_ids = [bytes.fromhex(txn)[::-1] for txn in txn_ids]
    >>> merkle_root(txn_ids)[::-1].hex()
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
    >>> # block 100,000
    >>> txn_ids = ["8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87", "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4", "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4", "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"]
    >>> txn_ids = [bytes.fromhex(txn)[::-1] for txn in txn_ids]
    >>> merkle_root(txn_ids)[::-1].hex()
    'f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766'
    >>> # block 100,002
    >>> txn_ids = ["ef1d870d24c85b89d92ad50f4631026f585d6a34e972eaf427475e5d60acf3a3", "f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07", "db60fb93d736894ed0b86cb92548920a3fe8310dd19b0da7ad97e48725e1e12e", "220ebc64e21abece964927322cba69180ed853bb187fbc6923bac7d010b9d87a", "71b3dbaca67e9f9189dad3617138c19725ab541ef0b49c05a94913e9f28e3f4e", "fe305e1ed08212d76161d853222048eea1f34af42ea0e197896a269fbf8dc2e0", "21d2eb195736af2a40d42107e6abd59c97eb6cffd4a5a7a7709e86590ae61987", "dd1fd2a6fc16404faf339881a90adbde7f4f728691ac62e8f168809cdfae1053", "74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20"]
    >>> txn_ids = [bytes.fromhex(txn)[::-1] for txn in txn_ids]
    >>> merkle_root(txn_ids)[::-1].hex()
    '2fda58e5959b0ee53c5253da9b9f3c0c739422ae04946966991cf55895287552'
    """
    row = copy.copy(txns)
    if len(row) == 1:
        return row[0]
    elif len(row) % 2:
        row += [row[-1]]
    while len(row) > 1:
        branches = []
        for i in range(0, len(row), 2):
            branches.append(bits.crypto.hash256(row[i] + row[i + 1]))
        row = branches
        if len(row) > 1 and len(row) % 2:
            row += [row[-1]]
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


def genesis_block(network: str = "mainnet"):
    """
    Hard coded genesis block
    Args:
        network: str, mainnet, testnet, or regtest

    >>> gb = genesis_block()
    >>> header = gb[:80]
    >>> import hashlib
    >>> hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    """
    if network.lower() == "mainnet":
        # https://github.com/bitcoin/bitcoin/blob/v0.1.5/main.cpp#L1495-L1498
        # https://github.com/bitcoin/bitcoin/blob/v28.0/src/kernel/chainparams.cpp#L135
        version: int = 1
        nTime = 1231006505
        nBits = 0x1D00FFFF
        nNonce = 2083236893
    elif network.lower() == "testnet":
        # https://github.com/bitcoin/bitcoin/blob/v28.0/src/kernel/chainparams.cpp#L254
        version: int = 1
        nTime = 1296688602
        nBits = 0x1D00FFFF
        nNonce = 414098458
    elif network.lower() == "regtest":
        # https://github.com/bitcoin/bitcoin/blob/v28.0/src/kernel/chainparams.cpp#L596
        version: int = 1
        nTime = 1296688602
        nBits = 0x207FFFFF
        nNonce = 2
    else:
        raise ValueError(f"network not recognized: {network}")

    coinbase_tx = genesis_coinbase_tx()
    merkle_ = merkle_root([bits.tx.txid(coinbase_tx)])
    return block_ser(
        block_header(1, NULL_32, merkle_, nTime, nBits.to_bytes(4, "little"), nNonce),
        [coinbase_tx],
    )


def block_ser(blk_hdr: bytes, txns: typing.List[bytes]) -> bytes:
    return blk_hdr + bits.compact_size_uint(len(txns)) + b"".join(txns)


def block_header_deser(blk_hdr: bytes) -> dict:
    assert len(blk_hdr) == 80, "block header not length 80"
    return {
        "version": int.from_bytes(blk_hdr[:4], "little"),
        "prev_blockheaderhash": blk_hdr[4:36][::-1].hex(),
        "merkle_root_hash": blk_hdr[36:68][::-1].hex(),
        "nTime": int.from_bytes(blk_hdr[68:72], "little"),
        "nBits": blk_hdr[72:76][::-1].hex(),
        "nNonce": int.from_bytes(blk_hdr[76:], "little"),
    }


def block_deser(block: bytes) -> dict:
    """
    Deserialize block data
    Args:
        block: bytes, block data
    """
    header = block[:80]
    number_of_txns, block_prime = bits.parse_compact_size_uint(block[80:])
    txns = []
    while block_prime:
        deserialized_tx, block_prime = bits.tx.tx_deser(block_prime, include_raw=True)
        txns.append(deserialized_tx)
    assert (
        len(txns) == number_of_txns
    ), "error during parsing - number of txns does not match"
    return block_header_deser(header) | {"txns": txns}
