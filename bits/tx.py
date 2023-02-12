"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
import os
import time
from hashlib import sha256
from typing import List
from typing import Optional

import bits.script.constants
from bits.base58 import base58check_decode
from bits.script.utils import p2pkh_script_sig
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
    from_addr: bytes,
    to_data: list,
    from_key: bytes = b"",
    to_addr_type: str = "p2pkh",
    miner_fee: int = 1000,
) -> bytes:
    """
    Create raw tx to send all funds (accounting for miner fee) from from_addr to various destinations
    Assumes p2pkh for from_addr
    Requires rpc bitcoind node
    Args:
        from_addr: bytes, sends from this addr
        to_data: list, addr type inferred per bits.script.utils.scriptpubkey function
        from_key: bytes, private key wif encoded
        miner_fee: int, amount (in satoshis) to include as miner fee
    """
    from_addr_txoutset = bits.rpc.rpc_method(
        "scantxoutset", "start", f'["addr({from_addr.decode("utf8")})"]'
    )
    txins = []
    for utxo in from_addr_txoutset["unspents"]:
        txid = bytes.fromhex(utxo["txid"])[::-1]
        from_addr_scriptsig = bytes.fromhex(utxo["scriptPubKey"])
        vout = utxo["vout"]
        txins.append(txin(outpoint(txid, vout), from_addr_scriptsig))
    total_amount = int(from_addr_txoutset["total_amount"] * 1e8)

    to_data_scriptpubkey = scriptpubkey(to_data, network=bits.bitsconfig["network"])
    txouts = [txout(total_amount - miner_fee, to_data_scriptpubkey)]

    tx_ = tx(txins, txouts)

    if from_key:
        # write key bytes as local tmp file for openssl signing
        _, key, compressed = wif_decode(from_key)

        timestamp = int(time.time() * 1000)
        sk_filename = f".bits/tmp/signing_key_{timestamp}.pem"
        with open(sk_filename, "wb") as file_:
            file_.write(pem_encode_key(key))

        # single hash since openssl does another
        sigdata = s_hash(tx_ + bits.script.constants.SIGHASH_ALL.to_bytes(4, "little"))

        # sign raw tx
        sig = bits.openssl.sign(sk_filename, stdin=sigdata)
        sig = ensure_sig_low_s(sig)

        # remove tmp file
        os.remove(sk_filename)

        from_addr_scriptsig = p2pkh_script_sig(
            sig, bits.keys.pub(key, compressed=compressed)
        )
        txins = []
        for utxo in from_addr_txoutset["unspents"]:
            txid = bytes.fromhex(utxo["txid"])[::-1]
            vout = utxo["vout"]
            txins.append(txin(outpoint(txid, vout), from_addr_scriptsig))
        tx_ = tx(txins, txouts)
    return tx_
