"""
Test spenditure of various transaction type via testmempoolaccept response on local bitcoind node via rpc
"""
import os
import time

import pytest

import bits.keys
from bits.base58 import base58check_decode
from bits.integrations import generate_funded_keys
from bits.integrations import mine_block
from bits.script.constants import SIGHASH_ALL
from bits.script.utils import multisig_script_pubkey
from bits.script.utils import multisig_script_sig
from bits.script.utils import p2pk_script_sig
from bits.script.utils import p2pkh_script_pubkey
from bits.script.utils import p2pkh_script_sig
from bits.script.utils import p2sh_multisig_script_pubkey
from bits.script.utils import p2sh_multisig_script_sig
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


def test_p2pk(funded_keys_101):
    wif_key_1, addr_1 = next(funded_keys_101)

    key_2 = bits.keys.key()
    pubkey_2 = bits.keys.pub(key_2)

    # pre-sig tx
    tx_ = send_tx(addr_1, pubkey_2, miner_fee=MINER_FEE)

    # sign
    _, key_1, compressed_pubkey = bits.utils.wif_decode(wif_key_1)
    pubkey_1 = bits.keys.pub(key_1, compressed=compressed_pubkey)
    sig = bits.utils.sig(key_1, tx_, sighash_flag=SIGHASH_ALL)
    scriptsig = p2pkh_script_sig(sig, pubkey_1)

    # create tx w/ scriptsig
    tx_ = send_tx(addr_1, pubkey_2, scriptsig=scriptsig, miner_fee=MINER_FEE)

    # testmempoolaccept and send and mine block
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()

    # pre-sig tx for p2pk spenditure
    tx_ = send_tx(pubkey_2, addr_1, miner_fee=MINER_FEE)

    # sign
    sig = bits.utils.sig(key_2, tx_, sighash_flag=SIGHASH_ALL)
    scriptsig = p2pk_script_sig(sig)

    # re-create w/ scriptsig
    tx_ = send_tx(pubkey_2, addr_1, scriptsig=scriptsig, miner_fee=MINER_FEE)

    # testmempoolaccept spenditure p2pk
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret


def test_p2pkh(funded_keys_101):
    wif_key_1, addr_1 = next(funded_keys_101)

    key_2 = bits.keys.key()
    pubkey_2 = bits.keys.pub(key_2)
    addr_2 = to_bitcoin_address(
        pubkey_hash(pubkey_2), addr_type="p2pkh", network="regtest"
    )

    # pre-sig tx
    tx_ = send_tx(addr_1, addr_2, miner_fee=MINER_FEE)

    # sign
    _, key_1, compressed_pubkey = bits.utils.wif_decode(wif_key_1)
    pubkey_1 = bits.keys.pub(key_1, compressed=compressed_pubkey)
    sig = bits.utils.sig(key_1, tx_, sighash_flag=SIGHASH_ALL)
    scriptsig = p2pkh_script_sig(sig, pubkey_1)

    # create tx w/ scriptsig
    tx_ = send_tx(addr_1, addr_2, scriptsig=scriptsig, miner_fee=MINER_FEE)

    # testmempoolaccept and send and mine block
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()

    # pre-sig tx for p2pkh spenditure
    tx_ = send_tx(addr_2, addr_1, miner_fee=MINER_FEE)

    # sign
    sig = bits.utils.sig(key_2, tx_, sighash_flag=SIGHASH_ALL)
    scriptsig = p2pkh_script_sig(sig, pubkey_2)

    # re-create w/ scriptsig
    tx_ = send_tx(addr_2, addr_1, scriptsig=scriptsig, miner_fee=MINER_FEE)

    # testmempoolaccept spenditure p2pkh
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret


def test_multisig(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        wif_key_1, addr_1 = next(funded_keys_101)

        # pre-sig tx
        tx_ = send_tx(
            addr_1,
            multisig_script_pubkey(m, pubkeys),
            miner_fee=MINER_FEE,
        )

        # sign
        _, key_1, compressed_pubkey = bits.utils.wif_decode(wif_key_1)
        pubkey_1 = bits.keys.pub(key_1, compressed=compressed_pubkey)
        sig = bits.utils.sig(key_1, tx_, sighash_flag=SIGHASH_ALL)
        scriptsig = p2pkh_script_sig(sig, pubkey_1)

        # re-create tx w/ scriptsig
        tx_ = send_tx(
            addr_1,
            multisig_script_pubkey(m, pubkeys),
            scriptsig=scriptsig,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()

        # pre-sig for multisig spenditure
        tx_ = send_tx(multisig_script_pubkey(m, pubkeys), addr_1, miner_fee=MINER_FEE)

        # sign (note: this does not do all permutations of valid sigs for m of n multisig)
        sigs = [
            bits.utils.sig(keys[i], tx_, sighash_flag=SIGHASH_ALL) for i in range(m)
        ]
        scriptsig = multisig_script_sig(sigs)

        # re-create w/ scriptsig
        tx_ = send_tx(
            multisig_script_pubkey(m, pubkeys),
            addr_1,
            scriptsig=scriptsig,
            miner_fee=MINER_FEE,
        )

        # testmempoolaccept spenditure multisig
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret


def test_p2sh_multisig(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        wif_key_1, addr_1 = next(funded_keys_101)

        # pre-sig tx
        tx_ = send_tx(
            addr_1,
            to_bitcoin_address(
                script_hash(multisig_script_pubkey(m, pubkeys)),
                addr_type="p2sh",
                network="regtest",
            ),
            miner_fee=MINER_FEE,
        )

        # sign
        _, key_1, compressed_pubkey = bits.utils.wif_decode(wif_key_1)
        pubkey_1 = bits.keys.pub(key_1, compressed=compressed_pubkey)
        sig = bits.utils.sig(key_1, tx_, sighash_flag=SIGHASH_ALL)
        scriptsig = p2pkh_script_sig(sig, pubkey_1)

        # re-create tx w/ scriptsig
        tx_ = send_tx(
            addr_1,
            to_bitcoin_address(
                script_hash(multisig_script_pubkey(m, pubkeys)),
                addr_type="p2sh",
                network="regtest",
            ),
            scriptsig=scriptsig,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()

        # pre-sig for p2sh-multisig spenditure (note scriptsig is redeem script)
        tx_ = send_tx(
            to_bitcoin_address(
                script_hash(multisig_script_pubkey(m, pubkeys)),
                addr_type="p2sh",
                network="regtest",
            ),
            addr_1,
            scriptsig=multisig_script_pubkey(m, pubkeys),
            miner_fee=MINER_FEE,
        )

        # sign (note: this does not do all permutations of valid sigs for m of n multisig)
        sigs = [
            bits.utils.sig(keys[i], tx_, sighash_flag=SIGHASH_ALL) for i in range(m)
        ]
        scriptsig = p2sh_multisig_script_sig(sigs, multisig_script_pubkey(m, pubkeys))

        # re-create w/ scriptsig
        tx_ = send_tx(
            to_bitcoin_address(
                script_hash(multisig_script_pubkey(m, pubkeys)),
                addr_type="p2sh",
                network="regtest",
            ),
            addr_1,
            scriptsig=scriptsig,
            miner_fee=MINER_FEE,
        )

        # testmempoolaccept spenditure multisig
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret


def test_p2wpkh(funded_keys_101):
    wif_key_0, addr_0 = next(funded_keys_101)

    key_1 = bits.keys.key()
    addr_1 = to_bitcoin_address(
        pubkey_hash(bits.keys.pub(key_1, compressed=True)),
        witness_version=0,
        network="regtest",
    )

    tx_ = send_tx(addr_0, addr_1, miner_fee=MINER_FEE)

    # sign
    _, key_0, compressed_pubkey = bits.utils.wif_decode(wif_key_0)
    pubkey_0 = bits.keys.pub(key_0, compressed=compressed_pubkey)
    sig = bits.utils.sig(key_0, tx_, sighash_flag=SIGHASH_ALL)
    scriptsig = p2pkh_script_sig(sig, pubkey_0)

    tx_ = send_tx(addr_0, addr_1, scriptsig=scriptsig, miner_fee=MINER_FEE)

    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()

    tx_ = send_tx(addr_1, addr_0, miner_fee=MINER_FEE)
    # TODO: test spenditure


def test_p2wsh(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        wif_key_0, addr_0 = next(funded_keys_101)

        tx_ = send_tx(
            addr_0,
            to_bitcoin_address(
                witness_script_hash(multisig_script_pubkey(m, pubkeys)),
                addr_type="p2sh",
                witness_version=0,
                network="regtest",
            ),
            miner_fee=MINER_FEE,
        )

        # sign
        _, key_0, compressed_pubkey = bits.utils.wif_decode(wif_key_0)
        pubkey_0 = bits.keys.pub(key_0, compressed=compressed_pubkey)
        sig = bits.utils.sig(key_0, tx_, sighash_flag=SIGHASH_ALL)
        scriptsig = p2pkh_script_sig(sig, pubkey_0)

        tx_ = send_tx(
            addr_0,
            to_bitcoin_address(
                witness_script_hash(multisig_script_pubkey(m, pubkeys)),
                addr_type="p2sh",
                witness_version=0,
                network="regtest",
            ),
            scriptsig=scriptsig,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()
        # TODO: test spenditure


def test_p2sh_p2wpkh(funded_keys_101):
    wif_key_0, addr_0 = next(funded_keys_101)

    key_1 = bits.keys.key()
    pk_hash_1 = pubkey_hash(bits.keys.pub(key_1, compressed=True))
    addr_1 = to_bitcoin_address(
        script_hash(p2wpkh_script_pubkey(pk_hash_1, witness_version=0)),
        addr_type="p2sh",
        network="regtest",
    )

    tx_ = send_tx(addr_0, addr_1, miner_fee=MINER_FEE)

    # sign
    _, key_0, compressed_pubkey = bits.utils.wif_decode(wif_key_0)
    pubkey_0 = bits.keys.pub(key_0, compressed=compressed_pubkey)
    sig = bits.utils.sig(key_0, tx_, sighash_flag=SIGHASH_ALL)
    scriptsig = p2pkh_script_sig(sig, pubkey_0)

    tx_ = send_tx(addr_0, addr_1, scriptsig=scriptsig, miner_fee=MINER_FEE)

    #
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    mine_block()
    # TODO: test spenditure


def test_p2sh_p2wsh(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]
    for m in range(1, 4):
        wif_key_0, addr_0 = next(funded_keys_101)

        tx_ = send_tx(
            addr_0,
            to_bitcoin_address(
                script_hash(
                    p2wsh_script_pubkey(
                        witness_script_hash(multisig_script_pubkey(m, pubkeys)),
                        witness_version=0,
                    )
                ),
                addr_type="p2sh",
                network="regtest",
            ),
            miner_fee=MINER_FEE,
        )

        # sign
        _, key_0, compressed_pubkey = bits.utils.wif_decode(wif_key_0)
        pubkey_0 = bits.keys.pub(key_0, compressed=compressed_pubkey)
        sig = bits.utils.sig(key_0, tx_, sighash_flag=SIGHASH_ALL)
        scriptsig = p2pkh_script_sig(sig, pubkey_0)

        tx_ = send_tx(
            addr_0,
            to_bitcoin_address(
                script_hash(
                    p2wsh_script_pubkey(
                        witness_script_hash(multisig_script_pubkey(m, pubkeys)),
                        witness_version=0,
                    )
                ),
                addr_type="p2sh",
                network="regtest",
            ),
            scriptsig=scriptsig,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        mine_block()
        # TODO: test spenditure
