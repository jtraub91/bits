"""
Test expected mempoolaccept response on local bitcoind node via rpc for various transaction types 
"""
import os
import time

import pytest

import bits.keys
import bits.openssl
import bits.script.constants
from bits.base58 import base58check_decode
from bits.integrations import generate_funded_keys
from bits.integrations import mine_block
from bits.script.utils import multisig_script_pubkey
from bits.script.utils import multisig_script_sig
from bits.script.utils import p2pkh_script_pubkey
from bits.script.utils import p2pkh_script_sig
from bits.script.utils import p2sh_multisig_script_pubkey
from bits.script.utils import p2sh_p2wpkh_script_pubkey
from bits.script.utils import p2wpkh_script_pubkey
from bits.script.utils import p2wsh_script_pubkey
from bits.tx import outpoint
from bits.tx import send_tx
from bits.tx import tx
from bits.tx import txin
from bits.tx import txout
from bits.utils import compute_point
from bits.utils import ensure_sig_low_s
from bits.utils import pem_encode_key
from bits.utils import pubkey
from bits.utils import pubkey_hash
from bits.utils import s_hash
from bits.utils import script_hash
from bits.utils import to_bitcoin_address
from bits.utils import witness_script_hash


MINER_FEE = 1000  # satoshis


def test_mempoolaccept_p2pk(funded_keys_101):
    key_1, addr_1 = next(funded_keys_101)

    key_2 = bits.keys.key()
    pubkey_2 = bits.keys.pub(key_2)

    addr_1_txoutset = bits.rpc.rpc_method(
        "scantxoutset", "start", f'["addr({addr_1.decode("utf8")})"]'
    )
    net_send_value = int(addr_1_txoutset["total_amount"] * 1e8) - MINER_FEE

    tx_ = send_tx(addr_1, [pubkey_2], from_key=key_1, miner_fee=MINER_FEE)

    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()


def test_mempoolaccept_p2pkh(funded_keys_101):
    key_1, addr_1 = next(funded_keys_101)

    key_2 = bits.keys.key()
    addr_2 = to_bitcoin_address(
        pubkey_hash(bits.keys.pub(key_2)), addr_type="p2pkh", network="regtest"
    )

    addr_1_txoutset = bits.rpc.rpc_method(
        "scantxoutset", "start", f'["addr({addr_1.decode("utf8")})"]'
    )
    net_send_value = int(addr_1_txoutset["total_amount"] * 1e8) - MINER_FEE

    tx_ = send_tx(addr_1, [addr_2], from_key=key_1, miner_fee=MINER_FEE)

    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()


def test_mempoolaccept_multisig(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        key_1, addr_1 = next(funded_keys_101)
        tx_ = send_tx(addr_1, [m] + pubkeys, from_key=key_1, miner_fee=MINER_FEE)
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()


def test_mempoolaccept_p2sh_multisig(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        key_0, addr_0 = next(funded_keys_101)

        tx_ = send_tx(
            addr_0,
            [
                to_bitcoin_address(
                    script_hash(multisig_script_pubkey(m, pubkeys)),
                    addr_type="p2sh",
                    network="regtest",
                )
            ],
            from_key=key_0,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()


def test_mempoolaccept_p2wpkh(funded_keys_101):
    key_0, addr_0 = next(funded_keys_101)

    key_1 = bits.keys.key()
    addr_1 = to_bitcoin_address(
        pubkey_hash(bits.keys.pub(key_1, compressed=True)),
        addr_type="p2pkh",
        witness_version=0,
        network="regtest",
    )

    addr_0_txoutset = bits.rpc.rpc_method(
        "scantxoutset", "start", f'["addr({addr_0.decode("utf8")})"]'
    )
    net_send_value = int(addr_0_txoutset["total_amount"] * 1e8) - MINER_FEE

    tx_ = send_tx(addr_0, [addr_1], from_key=key_0, miner_fee=MINER_FEE)

    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()


def test_mempoolaccept_p2wsh(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        key_0, addr_0 = next(funded_keys_101)

        tx_ = send_tx(
            addr_0,
            [
                to_bitcoin_address(
                    witness_script_hash(multisig_script_pubkey(m, pubkeys)),
                    addr_type="p2sh",
                    witness_version=0,
                    network="regtest",
                )
            ],
            from_key=key_0,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()


def test_mempoolaccept_p2sh_p2wpkh(funded_keys_101):
    key_0, addr_0 = next(funded_keys_101)

    key_1 = bits.keys.key()
    pk_hash_1 = pubkey_hash(bits.keys.pub(key_1, compressed=True))
    addr_1 = to_bitcoin_address(
        script_hash(p2wpkh_script_pubkey(pk_hash_1, witness_version=0)),
        addr_type="p2sh",
        network="regtest",
    )

    addr_0_txoutset = bits.rpc.rpc_method(
        "scantxoutset", "start", f'["addr({addr_0.decode("utf8")})"]'
    )
    net_send_value = int(addr_0_txoutset["total_amount"] * 1e8) - MINER_FEE

    tx_ = send_tx(addr_0, [addr_1], from_key=key_0, miner_fee=MINER_FEE)

    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()


def test_mempoolaccept_p2sh_p2wsh(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        key_0, addr_0 = next(funded_keys_101)

        tx_ = send_tx(
            addr_0,
            [
                to_bitcoin_address(
                    script_hash(
                        p2wsh_script_pubkey(
                            witness_script_hash(multisig_script_pubkey(m, pubkeys)),
                            witness_version=0,
                        )
                    ),
                    addr_type="p2sh",
                    network="regtest",
                )
            ],
            from_key=key_0,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()
