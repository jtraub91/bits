"""
blockchain lulz :P
"""
import copy
import json
import logging
import time
from typing import List, Union

import bits.constants
import bits.crypto
import bits.script
import bits.tx

log = logging.getLogger(__name__)


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


class Block(Bytes):
    def __new__(cls, data, **kwargs):
        cls._deserializer_fun = block_deser
        cls._serializer_fun = block
        return super().__new__(cls, data, **kwargs)

    def __getitem__(self, key: str):
        if key == "blockheaderhash":
            # just hash the first 80 bytes, instead of deserializing entire block
            return bits.crypto.hash256(self[:80])[::-1].hex()
        return super().__getitem__(key)


class Blockheader(Bytes):
    def __new__(cls, data, **kwargs):
        cls._deserializer_fun = block_header_deser
        cls._serializer_fun = block_header
        return super().__new__(cls, data, **kwargs)


def calculate_new_target(elapsed_time: int, current_target: int) -> int:
    """
    Calculate the new target for the next block

    Uses integer math for precision
    Args:
        elapsed_time: int, time elapsed between first and last blocks of difficulty period
        current_target: int, current target threshold
    Returns:
        new_target: int, new target threshold
    """
    target_time = 2016 * 10 * 60
    ratio = elapsed_time / target_time

    if ratio > 4:
        elapsed_time = 4
        target_time = 1
    elif ratio < 0.25:
        elapsed_time = 1
        target_time = 4

    new_target = current_target * elapsed_time // target_time
    if new_target > bits.constants.MAX_TARGET:
        new_target = bits.constants.MAX_TARGET
    return new_target


def target_threshold(nBits: bytes) -> int:
    """
    Calculate target threshold from compact nBits
    # https://developer.bitcoin.org/reference/block_chain.html#target-nbits
    Args:
        nBits: bytes, internal byte order
    >>> target = target_threshold(bytes.fromhex("207fffff")[::-1])
    >>> hex(target)
    '0x7fffff0000000000000000000000000000000000000000000000000000000000'
    >>> target = target_threshold(bytes.fromhex("1d00ffff")[::-1])
    >>> hex(target)
    '0xffff0000000000000000000000000000000000000000000000000000'
    """
    mantissa = nBits[:3]
    exponent = int.from_bytes(nBits[3:], "little")
    target = int.from_bytes(mantissa, "little") * 256 ** (exponent - len(mantissa))
    return target


def compact_nbits(target: int) -> bytes:
    """
    Convert target threshold to difficulty nBits compact representation
    Args:
        target: int, target threshold
    >>> compact_nbits(0x7fffff0000000000000000000000000000000000000000000000000000000000)[::-1].hex()
    '207fffff'
    >>> compact_nbits(0xffff0000000000000000000000000000000000000000000000000000)[::-1].hex()
    '1d00ffff'
    """
    if target > bits.constants.MAX_TARGET_REGTEST:
        raise ValueError("target greater than max")
    if target == bits.constants.MAX_TARGET:
        # special case that doesn't follow non-zero MSB in mantissa rule,
        # and we already know the value
        return b"\xff\xff\x00\x1d"
    target_bytes = target.to_bytes(32, "big")
    bytes_shifted = 0
    while target_bytes[0] == 0:
        # shift left until we get value in most significant byte
        target <<= 8
        target_bytes = target.to_bytes(32, "big")
        bytes_shifted += 1
    target >>= 29 * 8  # finally shift back 29 bytes to truncate
    if target > 0x7FFFFF:
        target >>= 8
        bytes_shifted -= 1
    mantissa = target.to_bytes(
        3, "little"
    )  # take 3 bytes, little endian (internal byte order)
    exponent = (32 - bytes_shifted).to_bytes(1, "little")
    return mantissa + exponent


def difficulty(target: int, network: str = "mainnet") -> float:
    """
    difficulty = difficulty_1_target / current_target
    https://en.bitcoin.it/wiki/Difficulty
    >>> difficulty(bits.constants.MAX_TARGET)
    1.0
    """
    if network == "mainnet" or network == "testnet":
        return bits.constants.MAX_TARGET / target
    elif network == "regtest":
        return bits.constants.MAX_TARGET_REGTEST / target
    else:
        raise ValueError(f"unrecognized network: {network}")


def target(diff: float, network: str = "mainnet") -> int:
    """
    Calculate target from difficulty
    https://en.bitcoin.it/wiki/Target
    Args:
        diff: float, difficulty
        network: str, mainnet, testnet, or regtest
    Returns:
        target
    >>> hex(target(1.0))
    '0xffff0000000000000000000000000000000000000000000000000000'
    """
    if diff < 1.0:
        raise ValueError(f"difficulty can't be lower than 1.0: {diff}")
    if network == "mainnet" or network == "testnet":
        return int(bits.constants.MAX_TARGET / diff)
    elif network == "regtest":
        return int(bits.constants.MAX_TARGET_REGTEST / diff)
    else:
        raise ValueError(f"unrecognized network: {network}")


def work(target_: int) -> int:
    # https://learnmeabitcoin.com/technical/blockchain/longest-chain/#chainwork
    # https://bitcoin.stackexchange.com/a/26894/135678
    return (2**256) // (target_ + 1)


def chainwork(work_: int) -> str:
    """
    Convert work to chainwork str representation
    """
    return work_.to_bytes(32, "big").hex()


def new_chainwork(prev_chainwork: str, nbits_: str) -> str:
    """
    Calculate new chainwork from previous chainwork and new nbits
    Args:
        prev_chainwork: str, previous chainwork (big endian)
        nbits_: str, nBits encoding of target threshold (big endian)
    """
    return chainwork(
        int(prev_chainwork, 16) + work(target_threshold(bytes.fromhex(nbits_)[::-1]))
    )


def block_header(
    version: int,
    prev_blockheaderhash: str,
    merkle_root_hash: str,
    nTime: int,
    nBits: str,
    nNonce: int,
    **kwargs,
) -> bytes:
    """
    Create serialized block header from args

    # https://developer.bitcoin.org/reference/block_chain.html#block-headers

    Args:
        version: int, block version
        prev_blockheaderhash: str, hash of previous block header (rpc byte order)
        merkle_root_hash: str, merkle root hash (rpc byte order)
        ntime: int, Unix epoch time
        nBits: str, nBits encoding of target threshold (rpc byte order)
        nNonce: int, arbitrary number
    Returns:
        block header

    >>> merkle_root_hash = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    >>> nBits = "1d00ffff"
    >>> bits.crypto.hash256(block_header(1, bits.constants.NULL_32.hex(), merkle_root_hash, 1231006505, nBits, 2083236893))[::-1].hex()
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    """
    return (
        version.to_bytes(4, "little")
        + bytes.fromhex(prev_blockheaderhash)[::-1]
        + bytes.fromhex(merkle_root_hash)[::-1]
        + nTime.to_bytes(4, "little")
        + bytes.fromhex(nBits)[::-1]
        + nNonce.to_bytes(4, "little")
    )


def merkle_root(txns: List[bytes]) -> bytes:
    """
    merkle root from a list of transaction ids
    https://developer.bitcoin.org/reference/block_chain.html#merkle-trees

    Args:
        txns: list[bytes], list of txids in internal byte order

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


def genesis_coinbase_tx() -> bytes:
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
        [
            bits.tx.txout(
                50 * bits.constants.COIN, bits.script.p2pk_script_pubkey(satoshis_pk)
            )
        ],
    )
    return coinbase_tx


def genesis_block(network: str = "mainnet") -> bytes:
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
    merkle_ = merkle_root([bytes.fromhex(bits.tx.txid(coinbase_tx))[::-1]])
    return block_ser(
        block_header(
            1,
            bits.constants.NULL_32[::-1].hex(),
            merkle_[::-1].hex(),
            nTime,
            nBits.to_bytes(4, "big").hex(),
            nNonce,
        ),
        [coinbase_tx],
    )


def block(
    version: int,
    prev_blockheaderhash: str,
    merkle_root_hash: str,
    nTime: int,
    nBits: str,
    nNonce: int,
    txns: List[dict],
    **kwargs,
) -> bytes:
    """
    Create serialized block from args

    Args:
        version: int, block version
        prev_blockheaderhash: str, hash of previous block header (big endian)
        merkle_root_hash: str, merkle root hash (big endian)
        ntime: int, Unix epoch time
        nBits: str, nBits encoding of target threshold (big endian byte order)
        nNonce: int, arbitrary number
        txns: list[bytes], list of transaction dictionaries
    Returns:
        block

    """
    return block_ser(
        block_header(
            version,
            prev_blockheaderhash,
            merkle_root_hash,
            nTime,
            nBits,
            nNonce,
        ),
        [bits.tx.tx(**txn) for txn in txns],
    )


def block_ser(blk_hdr: bytes, txns: List[bytes], **kwargs) -> bytes:
    return blk_hdr + bits.compact_size_uint(len(txns)) + b"".join(txns)


def block_header_deser(blk_hdr: bytes) -> dict:
    assert len(blk_hdr) == 80, "block header not length 80"
    return {
        "blockheaderhash": bits.crypto.hash256(blk_hdr)[::-1].hex(),
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

    Includes BIP34 parsing of blockheight from coinbase tx txin scriptsig
        for version 2 blocks
    https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki

    Args:
        block: bytes, block data
    Returns:
        dict, block dictionary
    """
    header = block[:80]
    number_of_txns, block_prime = bits.parse_compact_size_uint(block[80:])
    txns = []
    coinbase_tx_deser, block_prime = bits.tx.tx_deser(block_prime, include_raw=True)
    txns.append(coinbase_tx_deser)
    while block_prime:
        deserialized_tx, block_prime = bits.tx.tx_deser(block_prime, include_raw=True)
        txns.append(deserialized_tx)
    assert (
        len(txns) == number_of_txns
    ), "error during parsing - number of txns does not match"
    header_dict = block_header_deser(header)
    if header_dict["version"] == 2:
        coinbase_scriptsig = bytes.fromhex(coinbase_tx_deser["txins"][0]["scriptsig"])
        num_bytes = coinbase_scriptsig[0]
        blockheight = int.from_bytes(coinbase_scriptsig[1 : num_bytes + 1], "little")
        header_dict = {"blockheight": blockheight} | header_dict
    return header_dict | {"txns": txns}


def check_blockheader(blockheader: Blockheader, network: str = "mainnet") -> bool:
    """
    Checks blockheader for internal consisency (does not include context dependent checks)
    Args:
        blockheader: Blockheader
        network: str
    """

    if blockheader["nTime"] > time.time() + 7200:
        log.error("block nTime is too far in the future")
        return False

    # validate nBits is below max
    target = target_threshold(bytes.fromhex(blockheader["nBits"])[::-1])
    if network.lower() == "mainnet" or network.lower() == "testnet":
        if target > bits.constants.MAX_TARGET:
            log.error(
                f"target {hex(target)} greater than max {hex(bits.constants.MAX_TARGET)}"
            )
            return False

    elif network.lower() == "regtest":
        if target > bits.constants.MAX_TARGET_REGTEST:
            log.error(
                f"target {hex(target)} greater than max {hex(bits.constants.MAX_TARGET_REGTEST)}"
            )
            return False
    else:
        raise ValueError(f"unrecognized network: {network}")

    # check POW - hash of block header is less than target threshold claimed by nBits
    blockheaderhash = bits.crypto.hash256(blockheader)
    target = target_threshold(bytes.fromhex(blockheader["nBits"])[::-1])
    if int.from_bytes(blockheaderhash, "little") >= target:
        log.error(
            f"POW not satisfied, {blockheaderhash[::-1].hex()} > {int.to_bytes(target, 32, 'big').hex()}"
        )
        return False

    return True


def check_block(block: Union[Block, Bytes, bytes], network: str = "mainnet") -> bool:
    """
    Performs several block validation checks that are independent of context

    Full block validation happens in bits.p2p.Node and involves validating the block
        is the correct new block in the context of the existing chain

    inspiration https://github.com/bitcoin/bitcoin/blob/v0.2.13/main.cpp#L1280

    Args:
        block: Block, block data
        network: str, mainnet, testnet, or regtest
    Returns:
        bool, True if block is valid, else False
    """
    block = Block(block)
    # check block size is less than MAX_BLOCK_SIZE
    if len(block) == 0:
        log.error("block is empty")
        return False
    if len(block) > bits.constants.MAX_SIZE:
        log.error("block is larger than MAX_SIZE")
        return False

    if block["nTime"] > time.time() + 7200:
        log.error("block nTime is too far in the future")
        return False

    # check that first transaction is coinbase tx
    txns = block["txns"]
    if len(txns) == 0:
        log.error("block has no transactions")
        return False
    if not bits.tx.is_coinbase(txns[0]):
        log.error("first block is not coinbase transction")
        return False
    # check there is not more than one coinbase
    for txn in txns[1:]:
        if bits.tx.is_coinbase(txn):
            log.error("more than one coinbase")
            return False

    # validate nBits is below max
    target = target_threshold(bytes.fromhex(block["nBits"])[::-1])
    if network.lower() == "mainnet" or network.lower() == "testnet":
        if target > bits.constants.MAX_TARGET:
            log.error(
                f"target {hex(target)} greater than max {hex(bits.constants.MAX_TARGET)}"
            )
            return False
    elif network.lower() == "regtest":
        if target > bits.constants.MAX_TARGET_REGTEST:
            log.error(
                f"target {hex(target)} greater than max {hex(bits.constants.MAX_TARGET_REGTEST)}"
            )
            return False
    else:
        raise ValueError(f"unrecognized network: {network}")

    # check POW - hash of block header is less than target threshold claimed by nBits
    blockhash = bits.crypto.hash256(block[:80])[::-1].hex()
    target = target_threshold(bytes.fromhex(block["nBits"])[::-1])
    if int.from_bytes(bytes.fromhex(blockhash), "big") >= target:
        log.error(
            f"POW not satisfied, {blockhash} > {int.to_bytes(target, 32, 'big').hex()}"
        )
        return False

    # check merkle root matches transactions
    merkle_root_hash = merkle_root(
        [bytes.fromhex(txn["txid"])[::-1] for txn in block["txns"]]
    )[::-1].hex()
    if block["merkle_root_hash"] != merkle_root_hash:
        log.error(
            f"merkle root hash {block['merkle_root_hash']} does not match internal computation from block transactions  {merkle_root_hash}"
        )
        return False

    return True


def median_time(times: List[int]) -> Union[int | None]:
    """
    Return the median time

    Consensus rules use the last 11 blocks to compute the median

    Args:
        times: List[int], list of integer times
    """
    if len(times) == 0:
        return None
    if len(times) == 1:
        return times[0]
    times = sorted(times)
    if len(times) % 2:
        # odd
        median = times[len(times) // 2]
    else:
        median = (times[len(times) // 2 - 1] + times[len(times) // 2]) // 2
    return median


def block_reward(blockheight: int) -> int:
    """
    get the block reward for a given blockheight
    """
    reward = 50 * bits.constants.COIN
    reward >>= int(blockheight / 210000)
    return reward
