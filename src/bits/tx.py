"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
import logging
from typing import List, Optional, Tuple, Union

import bits.constants
import bits.crypto
import bits.keys
import bits.script
from bits import Bytes

log = logging.getLogger(__name__)


def outpoint(txid_: bytes, index: int) -> bytes:
    """
    # https://developer.bitcoin.org/reference/transactions.html#outpoint-the-specific-part-of-a-specific-output

    Args:
        txid_: bytes, txid (little endian)
        index: int, output index
    """
    return txid_ + index.to_bytes(4, "little")


def txin(
    prev_outpoint: bytes,
    script_sig: bytes,
    sequence: bytes = b"\xff\xff\xff\xff",
) -> bytes:
    """
    Tx input serialization
    Args:
        prev_outpoint: bytes
        script_sig: bytes
        sequence: bytes, sequence (little endian byte order)
    """
    return (
        prev_outpoint + bits.compact_size_uint(len(script_sig)) + script_sig + sequence
    )


def txin_ser(txin_: dict) -> bytes:
    return txin(
        outpoint(bytes.fromhex(txin_["txid"]), txin_["vout"]),
        bytes.fromhex(txin_["scriptsig"]),
        sequence=txin_["sequence"].to_bytes(4, "little"),
    )


def txin_deser(txin_: bytes, **kwargs) -> Tuple[dict, bytes]:
    txid_ = txin_[:32]
    vout = txin_[32:36]
    scriptsig_len, txin_prime = bits.parse_compact_size_uint(txin_[36:])
    scriptsig = txin_prime[:scriptsig_len]
    sequence = txin_prime[scriptsig_len : scriptsig_len + 4]
    txin_ = txin_prime[scriptsig_len + 4 :]
    return {
        "txid": txid_[::-1].hex(),  # rpc byte order
        "vout": int.from_bytes(vout, "little"),
        "scriptsig": scriptsig.hex(),
        "sequence": int.from_bytes(sequence, "little"),
    }, txin_


def txout(value: int, script_pubkey: bytes) -> bytes:
    """
    Serialize txout
    Args:
        value: int, value in satoshis
        script_pubkey: bytes, scriptpubkey (big endian)
    Returns:
        bytes, serialized txout
    """
    return (
        value.to_bytes(8, "little")
        + bits.compact_size_uint(len(script_pubkey))
        + script_pubkey
    )


def txout_ser(txout_: dict) -> bytes:
    return txout(
        txout_["value"],
        bytes.fromhex(txout_["scriptpubkey"]),
    )


def txout_deser(txout_: bytes, **kwargs) -> Tuple[dict, bytes]:
    value = txout_[:8]
    scriptpubkey_len, txout_prime = bits.parse_compact_size_uint(txout_[8:])
    scriptpubkey = txout_prime[:scriptpubkey_len]
    txout_ = txout_prime[scriptpubkey_len:]
    return {
        "value": int.from_bytes(value, "little"),
        "scriptpubkey": scriptpubkey.hex(),
    }, txout_


def tx(
    txins: List[bytes],
    txouts: List[bytes],
    version: int = 1,
    locktime: int = 0,
    script_witnesses: List[bytes] = [],
) -> bytes:
    """
    Transaction serialization, optional SegWit per BIP 141
    """
    if script_witnesses:
        marker = b"\x00"
        flag = b"\x01"
        return (
            version.to_bytes(4, "little")
            + marker
            + flag
            + bits.compact_size_uint(len(txins))
            + b"".join(txins)
            + bits.compact_size_uint(len(txouts))
            + b"".join(txouts)
            + b"".join(script_witnesses)
            + locktime.to_bytes(4, "little")
        )
    return (
        version.to_bytes(4, "little")
        + bits.compact_size_uint(len(txins))
        + b"".join(txins)
        + bits.compact_size_uint(len(txouts))
        + b"".join(txouts)
        + locktime.to_bytes(4, "little")
    )


def txid(tx_: bytes) -> str:
    """
    Returns txid from tx bytes in big endian byte order
    """
    return bits.crypto.hash256(tx_)[::-1].hex()


def tx_ser(tx_: dict) -> bytes:
    """
    Serialize tx bytes from tx dict
    """
    return tx(
        [
            txin(
                outpoint(bytes.fromhex(txin_["txid"])[::-1], txin_["vout"]),
                bytes.fromhex(txin_["scriptsig"]),
                sequence=txin_["sequence"].to_bytes(4, "little"),
            )
            for txin_ in tx_["txins"]
        ],
        [
            txout(txout_["value"], bytes.fromhex(txout_["scriptpubkey"]))
            for txout_ in tx_["txouts"]
        ],
        version=tx_["version"],
        locktime=tx_["locktime"],
        script_witnesses=[
            bits.script.witness_ser(witness_stack)
            for witness_stack in tx_.get("witnesses", [])
        ],
    )


def tx_deser(tx_: bytes, json_serializable: bool = False) -> Tuple[dict, bytes]:
    """
    Deserialize tx data

    Args:
        tx_: bytes, tx data
        json_serializable: bool, set True to return txin and txouts as dicts instead of TxIn and TxOut objects, respectively
    Returns:
        tuple[dict, bytes], deserialized tx, leftover bytes
    """
    deserialized_tx = {}
    is_segwit = False
    version = tx_[:4]
    deserialized_tx["version"] = int.from_bytes(version, "little")

    number_of_inputs, tx_prime = bits.parse_compact_size_uint(tx_[4:])
    if number_of_inputs == 0 and tx_prime:
        assert tx_prime[0] == 1, "flag not 1"
        is_segwit = True
        number_of_inputs, tx_prime = bits.parse_compact_size_uint(tx_prime[1:])
    txins = []
    for _ in range(number_of_inputs):
        txin_, tx_prime = TxIn.from_bytestream(tx_prime)
        if json_serializable:
            txin_ = txin_.dict()
        txins.append(txin_)
    deserialized_tx["txins"] = txins

    number_of_outputs, tx_prime = bits.parse_compact_size_uint(tx_prime)
    txouts = []
    for _ in range(number_of_outputs):
        txout_, tx_prime = TxOut.from_bytestream(tx_prime)
        if json_serializable:
            txout_ = txout_.dict()
        txouts.append(txout_)
    deserialized_tx["txouts"] = txouts

    if is_segwit:
        deserialized_tx["witnesses"] = []
        for _ in range(len(txins)):
            txin_witness_stack, tx_prime = bits.script.parse_witness(tx_prime)
            if json_serializable:
                txin_witness_stack = [elem.hex() for elem in txin_witness_stack]
            deserialized_tx["witnesses"].append(txin_witness_stack)

    locktime = tx_prime[:4]
    deserialized_tx["locktime"] = int.from_bytes(locktime, "little")
    tx_prime = tx_prime[4:]
    tx_ = tx_.split(tx_prime)[0] if tx_prime else tx_

    # re-serialize without witness for txid
    legacy_tx = tx_ser(
        {key: value for key, value in deserialized_tx.items() if key != "witnesses"}
    )
    tx_dict = {"txid": txid(legacy_tx), "wtxid": txid(tx_)}
    tx_dict.update(deserialized_tx)
    return tx_dict, tx_prime


def coinbase_txin(
    coinbase_script: bytes,
    sequence: bytes = b"\xff\xff\xff\xff",
    block_height: Optional[int] = None,
) -> bytes:
    """
    Create coinbase txin with
        BIP34 blockheight prepended to coinbase script as minimally encoded serialized CScript,
        if blockheight is specified
    Args:
        coinbase_script: bytes, arbitrary data not exceeding 100 bytes
        sequence: bytes, sequence (little endian byte order)
        block_height: Optional[bytes], block height of this block
    """
    if block_height is not None:
        # "minimally encoded serialized CScript"
        if block_height <= 16:
            # TODO: wtf is this about?
            op = getattr(bits.constants, f"OP_{block_height}")
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
        outpoint(b"\x00" * 32, bits.constants.UINT32_MAX),  # null
        coinbase_script,
        sequence=sequence,
    )


def coinbase_tx(
    coinbase_script: bytes,
    script_pubkey: bytes,
    block_reward: Optional[int] = None,
    block_height: Optional[int] = None,
    regtest: bool = False,
    witness_merkle_root_hash: Optional[bytes] = None,
) -> bytes:
    """
    Create coinbase transaction by supplying arbitrary transaction input coinbase
    scriptsig and transaction output spending scriptpubkey.

    Optional block height (for version 2 blocks per BIP34) and block reward arguments
    may be provided. If block height is specified, the block reward must be <= max reward,
    and will be inferred to be == max reward if left unspecified.

    Args:
        coinbase_script: bytes, txin scriptsig of arbitrary data not exceeding 100 bytes
        script_pubkey: bytes, txout scriptpubkey
        block_reward: Optional[int], txout value in satoshis
        block_height: Optional[int], block height per BIP34
        regtest: bool, set True for regtest to calculate blocks per halving correctly
        witness_merkle_root_hash: Optional[bytes], per BIP141 specify witness merkle root,
            to be committed in a txout of the coinbase transaction
    Returns:
        coinbase tx

    """
    blocks_per_halving = 2016 if not regtest else 150

    if block_height:
        max_reward = int(50e8)
        halvings = block_height // 150
        if halvings:
            max_reward //= 2**halvings
        if block_reward:
            assert block_reward <= max_reward, "block reward too high"
        else:
            block_reward = max_reward

    txins = [coinbase_txin(coinbase_script, block_height=block_height)]
    txouts = [txout(block_reward, script_pubkey)]
    if witness_merkle_root_hash:
        commitment_header = b"\xAA\x21\xA9\xED"
        witness_commitment_scriptpubkey = bits.script.script(
            ["OP_RETURN", (commitment_header + witness_merkle_root_hash).hex()]
        )
        txouts.append(txout(0, witness_commitment_scriptpubkey))
    return tx(
        txins,
        txouts,
        script_witnesses=(
            [
                bits.script.script(
                    [bits.constants.WITNESS_RESERVED_VALUE.hex()], witness=True
                )
            ]
            if witness_merkle_root_hash
            else []
        ),
    )


def is_final(tx_: Union[bytes, dict], blockheight: int, blocktime: int) -> bool:
    """
    Check if tx is final based on locktime and the blockheight / blocktime of the block
        it is contained in
    Args:
        tx_: bytes | dict, transaction
        blockheight: int, block height of tx's block
        blocktime: int, timestamp of tx's block
    """
    # logic based on https://github.com/bitcoin/bitcoin/blob/v0.4.0/src/main.h#L435
    tx_dict = tx_deser(tx_) if type(tx_) is bytes else tx_
    txins = tx_dict["txins"]
    locktime = tx_dict["locktime"]
    if locktime == 0:
        return True
    locktime_comparison = (
        blockheight if locktime < bits.constants.LOCKTIME_THRESHOLD else blocktime
    )
    if locktime < locktime_comparison:
        return True
    for txi in txins:
        if txi["sequence"] != bits.constants.UINT32_MAX:
            return False
    return True


def assert_coinbase(tx_: Union[bytes, dict]) -> bool:
    """
    Assert tx is a coinbase transaction
    Args:
        tx_: bytes | dict, transaction bytes or dictionary
    Returns:
        True is tx is coinbase transaction
    Throws:
        AssertionError if tx is not a coinbase transaction
    """
    coinbase_tx = bits.tx.tx_deser(tx_) if type(tx_) is bytes else tx_
    coinbase_tx_txins = coinbase_tx["txins"]
    assert (
        len(coinbase_tx_txins) == 1
    ), "number of coinbase tx inputs must be equal to 1"

    coinbase_txin = coinbase_tx_txins[0]
    assert (
        bytes.fromhex(coinbase_txin["txid"])[::-1] == bits.constants.NULL_32
    ), "coinbase tx input prev outpoint must be NULL_32"

    assert (
        coinbase_txin["vout"] == bits.constants.UINT32_MAX
    ), "coinbase tx input prev outpoint index must be UINT32_MAX"
    return True


def is_coinbase(tx_: Union[bytes, dict], log_error: bool = False) -> bool:
    """
    Test whether transaction is a coinbase tx
    Args:
        tx_: bytes, transaction
        log_error: bool, set True to log assertion error, if any
    Returns:
        True if transaction is a coinbase transaction, else False
    """
    try:
        return assert_coinbase(tx_)
    except AssertionError as err:
        if log_error:
            log.error(err)
        return False


def check_tx(tx_: bytes) -> bool:
    """
    basic transaction checks that don't depend on blockchain context

    ref https://github.com/jtraub91/bitcoin/blob/v0.2.13/main.h#L460
    """
    tx_dict = tx_deser(tx_)[0]
    txins = tx_dict["txins"]
    txouts = tx_dict["txouts"]
    if len(txins) == 0:
        log.error("txins is empty")
        return False
    if len(txouts) == 0:
        log.error("txouts is empty")
        return False

    # check if any txout value is negative (shouldn't really happen?)
    for txo in tx_dict["txouts"]:
        if txo["value"] < 0:
            log.error("txout output with negative value")
            return False

    if is_coinbase(tx_):
        if len(bytes.fromhex(tx_dict["txins"]["scriptSig"])) < 2:
            log.error("coinbase tx input scriptsig must be 2 bytes or more")
            return False
        if len(bytes.fromhex(tx_dict["txins"]["scriptsig"])) > 100:
            log.error("coinbase tx input scriptsig must not exceed 100 bytes")
            return False
    else:
        for txi in tx_dict["txins"]:
            if bytes.fromhex(txi["txid"])[::-1] == b"\x00" * 32:
                log.error("prev outpoint is null")
                return False
    return True


class Tx(Bytes):
    def __new__(cls, data, **kwargs):
        cls._deserializer_fun = lambda data, **kwargs: tx_deser(data, **kwargs)[0]
        cls._serializer_fun = tx_ser
        return super().__new__(cls, data, **kwargs)

    def __getitem__(self, key: str):
        if key == "txid":
            return bits.crypto.hash256(self)[::-1].hex()
        return super().__getitem__(key)


class TxIn(Bytes):
    def __new__(cls, data, **kwargs):
        cls._deserializer_fun = lambda data: txin_deser(data)[0]
        cls._serializer_fun = txin_ser
        return super().__new__(cls, data, **kwargs)

    def __getitem__(self, key: str):
        if key == "outpoint":
            return outpoint(bytes.fromhex(self["txid"])[::-1], self["vout"])
        return super().__getitem__(key)

    @classmethod
    def from_bytestream(cls, bytestream: bytes) -> Tuple["TxIn", bytes]:
        txin_dict, leftover = txin_deser(bytestream)
        txin_ = bytestream.removesuffix(leftover)
        new_class = cls(txin_)
        new_class._dict = txin_dict
        return new_class, leftover


class TxOut(Bytes):
    def __new__(cls, data, **kwargs):
        cls._deserializer_fun = lambda data: txout_deser(data)[0]
        cls._serializer_fun = txout_ser
        return super().__new__(cls, data, **kwargs)

    @classmethod
    def from_bytestream(cls, bytestream: bytes) -> Tuple["TxOut", bytes]:
        txout_dict, leftover = txout_deser(bytestream)
        txout_ = bytestream.removesuffix(leftover)
        new_class = cls(txout_)
        new_class._dict = txout_dict
        return new_class, leftover
