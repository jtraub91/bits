"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
import os
import time
from hashlib import sha256
from typing import List
from typing import Optional
from typing import Tuple

import bits.keys
import bits.openssl
import bits.script.constants
import bits.utils
from bits.base58 import base58check_decode
from bits.script.utils import p2pkh_script_sig
from bits.script.utils import p2sh_script_sig
from bits.script.utils import scriptpubkey
from bits.utils import compact_size_uint
from bits.utils import d_hash
from bits.utils import ensure_sig_low_s
from bits.utils import pem_encode_key
from bits.utils import s_hash
from bits.utils import wif_decode

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


def txin_deser(txin_: bytes) -> Tuple[dict, bytes]:
    txid_ = txin_[:32]
    vout = txin_[32:36]
    scriptsig_len, txin_prime = bits.utils.parse_compact_size_uint(txin_[36:])
    scriptsig = txin_prime[:scriptsig_len]
    sequence = txin_prime[scriptsig_len : scriptsig_len + 4]
    txin_ = txin_prime[scriptsig_len + 4 :]
    return {
        "txid": txid_.hex(),
        "vout": int.from_bytes(vout, "little"),
        "scriptsig": scriptsig.hex(),
        "sequence": sequence.hex(),
    }, txin_


def txout(value: int, script_pubkey: bytes) -> bytes:
    return (
        value.to_bytes(8, "little")
        + compact_size_uint(len(script_pubkey))
        + script_pubkey
    )


def txout_deser(txout_: bytes) -> Tuple[dict, bytes]:
    value = txout_[:8]
    scriptpubkey_len, txout_prime = bits.utils.parse_compact_size_uint(txout_[8:])
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


def tx_deser(tx_: bytes) -> Tuple[dict, bytes]:
    deserialized_tx = {}
    is_segwit = False
    version = tx_[:4]
    deserialized_tx["version"] = int.from_bytes(version, "little")

    number_of_inputs, tx_prime = bits.utils.parse_compact_size_uint(tx_[4:])
    if number_of_inputs == 0 and tx_prime:
        assert tx_prime[0] == 1, "flag not 1"
        is_segwit = True
        number_of_inputs, tx_prime = bits.utils.parse_compact_size_uint(tx_prime[1:])
    txins = []
    for _ in range(number_of_inputs):
        txin_, tx_prime = txin_deser(tx_prime)
        txins.append(txin_)
    deserialized_tx["txins"] = txins

    number_of_outputs, tx_prime = bits.utils.parse_compact_size_uint(tx_prime)
    txouts = []
    for _ in range(number_of_outputs):
        txout_, tx_prime = txout_deser(tx_prime)
        txouts.append(txout_)
    deserialized_tx["txouts"] = txouts

    if is_segwit:
        number_of_witnesses, tx_prime = bits.utils.parse_compact_size_uint(tx_prime)
        script_witnesses, tx_prime = bits.utils.parse_script_witness(tx_prime)
        deserialized_tx["witnesses"] = script_witnesses

    locktime = tx_prime[:4]
    deserialized_tx["locktime"] = int.from_bytes(locktime, "little")

    tx_prime = tx_prime[4:]
    return deserialized_tx, tx_prime


def txid(tx_: bytes) -> str:
    return d_hash(tx_)[::-1].hex()  # rpc byte order


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
                max_reward //= 2**halvings
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


def send_tx(
    from_: bytes,
    to_: bytes,
    scriptsig: Optional[bytes] = b"",
    miner_fee: int = 1000,
) -> bytes:
    """
    Create raw transaction which sends all funds from addr to addr
    Assumes p2pkh for from_addr
    Requires rpc bitcoind node
    Args:
        from_: bytes, send from this output descriptor
        to_: bytes, send to this output descriptor
        scriptsig: bytes, list of keys (wif-encoded)
        miner_fee: int, amount (in satoshis) to include as miner fee
    """
    if bits.utils.is_point(from_):
        from_txoutset = from_txoutset = bits.rpc.rpc_method(
            "scantxoutset", "start", f'["pk({from_.hex()})"]'
        )
    elif bits.base58.is_base58check(from_) or bits.bips.bip173.is_segwit_addr(from_):
        from_txoutset = bits.rpc.rpc_method(
            "scantxoutset", "start", f'["addr({from_.decode("utf8")})"]'
        )
    else:
        # raw scriptpubkey
        from_txoutset = bits.rpc.rpc_method(
            "scantxoutset", "start", f'["raw({from_.hex()})"]'
        )

    txins = []
    for utxo in from_txoutset["unspents"]:
        txid = bytes.fromhex(utxo["txid"])[::-1]
        from_scriptsig = bytes.fromhex(utxo["scriptPubKey"])
        vout = utxo["vout"]
        txins.append(txin(outpoint(txid, vout), from_scriptsig))
    total_amount = int(from_txoutset["total_amount"] * 1e8)

    to_scriptpubkey = scriptpubkey(to_)
    txouts = [txout(total_amount - miner_fee, to_scriptpubkey)]

    tx_ = tx(txins, txouts)

    if scriptsig:
        txins = []
        for utxo in from_txoutset["unspents"]:
            txid = bytes.fromhex(utxo["txid"])[::-1]
            vout = utxo["vout"]
            txins.append(txin(outpoint(txid, vout), scriptsig))
        tx_ = tx(txins, txouts)
    return tx_
