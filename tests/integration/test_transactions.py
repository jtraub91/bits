"""
Test spenditure of various transaction type via testmempoolaccept response on local bitcoind node via rpc
"""
import bits.integrations
import bits.keys
import bits.script.constants
import bits.tx


MINER_FEE = 1000  # satoshis


def test_p2pk(funded_keys_101):
    wif_key_1, addr_1 = next(funded_keys_101)

    key_2 = bits.keys.key()
    pubkey_2 = bits.keys.pub(key_2)
    wif_key_2 = bits.wif_encode(key_2, addr_type="p2pk", network="regtest")

    tx_ = bits.tx.send_tx(
        addr_1,
        pubkey_2,
        from_keys=[wif_key_1],
        miner_fee=MINER_FEE,
        sighash_flag=bits.script.constants.SIGHASH_ALL,
    )

    # testmempoolaccept and send and mine block
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    bits.integrations.mine_block(b"")

    # test spenditure p2pk
    tx_ = bits.tx.send_tx(
        pubkey_2,
        addr_1,
        from_keys=[wif_key_2],
        miner_fee=MINER_FEE,
        sighash_flag=bits.script.constants.SIGHASH_ALL,
    )
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret


def test_p2pkh(funded_keys_101):
    wif_key_1, addr_1 = next(funded_keys_101)

    key_2 = bits.keys.key()
    pubkey_2 = bits.keys.pub(key_2)
    addr_2 = bits.to_bitcoin_address(
        bits.pubkey_hash(pubkey_2), addr_type="p2pkh", network="regtest"
    )
    wif_key_2 = bits.wif_encode(key_2, addr_type="p2pkh", network="regtest")

    # create tx w/ scriptsig
    tx_ = bits.tx.send_tx(
        addr_1,
        addr_2,
        from_keys=[wif_key_1],
        miner_fee=MINER_FEE,
        sighash_flag=bits.script.constants.SIGHASH_ALL,
    )

    # testmempoolaccept and send and mine block
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    bits.integrations.mine_block(b"")

    # test spenditure p2pkh
    tx_ = bits.tx.send_tx(
        addr_2,
        addr_1,
        from_keys=[wif_key_2],
        miner_fee=MINER_FEE,
        sighash_flag=bits.script.constants.SIGHASH_ALL,
    )
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret


def test_multisig(funded_keys_101):
    # note: does not test *all* permutations of valid sigs for m of n multisig
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]

    for m in range(1, 4):
        wif_key_1, addr_1 = next(funded_keys_101)

        tx_ = bits.tx.send_tx(
            addr_1,
            bits.script.multisig_script_pubkey(m, pubkeys),
            from_keys=[wif_key_1],
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        bits.integrations.mine_block(b"")

        # test spenditure multisig
        from_wif_keys = [
            bits.wif_encode(key, addr_type="multisig", network="regtest")
            for key in keys[:m]
        ]
        tx_ = bits.tx.send_tx(
            bits.script.multisig_script_pubkey(m, pubkeys),
            addr_1,
            from_keys=from_wif_keys,
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret


def test_p2sh_multisig(funded_keys_101):
    # note: does not test *all* permutations of valid sigs for m of n p2sh-multisig
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key) for key in keys]

    for m in range(1, 4):
        wif_key_1, addr_1 = next(funded_keys_101)

        redeem_script = bits.script.multisig_script_pubkey(m, pubkeys)
        to_addr = bits.to_bitcoin_address(
            bits.script_hash(redeem_script),
            addr_type="p2sh",
            network="regtest",
        )
        to_wif_keys = [
            bits.wif_encode(
                key, addr_type="p2sh", network="regtest", data=redeem_script
            )
            for key in keys[:m]
        ]
        tx_ = bits.tx.send_tx(
            addr_1,
            to_addr,
            from_keys=[wif_key_1],
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        bits.integrations.mine_block(b"")

        # test spenditure multisig
        tx_ = bits.tx.send_tx(
            to_addr,
            addr_1,
            from_keys=to_wif_keys,
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret


def test_p2wpkh(funded_keys_101):
    wif_key_0, addr_0 = next(funded_keys_101)

    key_1 = bits.keys.key()
    addr_1 = bits.to_bitcoin_address(
        bits.pubkey_hash(bits.keys.pub(key_1, compressed=True)),
        witness_version=0,
        network="regtest",
    )
    wif_key_1 = bits.wif_encode(key_1, addr_type="p2wpkh", network="regtest")

    tx_ = bits.tx.send_tx(
        addr_0,
        addr_1,
        from_keys=[wif_key_0],
        sighash_flag=bits.script.constants.SIGHASH_ALL,
        miner_fee=MINER_FEE,
    )
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    bits.integrations.mine_block(b"")

    tx_ = bits.tx.send_tx(
        addr_1,
        addr_0,
        from_keys=[wif_key_1],
        sighash_flag=bits.script.constants.SIGHASH_ALL,
        miner_fee=MINER_FEE,
    )
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret


def test_p2wsh(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key, compressed=True) for key in keys]
    for m in range(1, 4):
        wif_key_0, addr_0 = next(funded_keys_101)

        redeem_script = bits.script.multisig_script_pubkey(m, pubkeys)
        to_addr = bits.to_bitcoin_address(
            bits.witness_script_hash(redeem_script),
            addr_type="p2sh",
            witness_version=0,
            network="regtest",
        )
        to_wif_keys = [
            bits.wif_encode(
                key, addr_type="p2wsh", network="regtest", data=redeem_script
            )
            for key in keys[:m]
        ]

        tx_ = bits.tx.send_tx(
            addr_0,
            to_addr,
            from_keys=[wif_key_0],
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        bits.integrations.mine_block(b"")

        # test spenditure p2wsh
        tx_ = bits.tx.send_tx(
            to_addr,
            addr_0,
            from_keys=to_wif_keys,
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret


def test_p2sh_p2wpkh(funded_keys_101):
    wif_key_0, addr_0 = next(funded_keys_101)

    key_1 = bits.keys.key()
    pk_hash_1 = bits.pubkey_hash(bits.keys.pub(key_1, compressed=True))
    redeem_script = bits.script.p2wpkh_script_pubkey(pk_hash_1, witness_version=0)
    addr_1 = bits.to_bitcoin_address(
        bits.script_hash(redeem_script),
        addr_type="p2sh",
        network="regtest",
    )
    wif_key_1 = bits.wif_encode(
        key_1, addr_type="p2sh-p2wpkh", network="regtest", data=redeem_script
    )

    tx_ = bits.tx.send_tx(
        addr_0,
        addr_1,
        from_keys=[wif_key_0],
        sighash_flag=bits.script.constants.SIGHASH_ALL,
        miner_fee=MINER_FEE,
    )

    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret
    bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
    bits.integrations.mine_block(b"")

    # test spenditure p2sh-p2wpkh
    tx_ = bits.tx.send_tx(
        addr_1,
        addr_0,
        from_keys=[wif_key_1],
        sighash_flag=bits.script.constants.SIGHASH_ALL,
        miner_fee=MINER_FEE,
    )
    ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
    assert ret[0]["allowed"] == True, ret


def test_p2sh_p2wsh(funded_keys_101):
    keys = [bits.keys.key() for i in range(3)]
    pubkeys = [bits.keys.pub(key, compressed=True) for key in keys]
    for m in range(1, 4):
        wif_key_0, addr_0 = next(funded_keys_101)

        witness_script = bits.script.multisig_script_pubkey(m, pubkeys)
        redeem_script = bits.script.p2wsh_script_pubkey(
            bits.witness_script_hash(witness_script),
            witness_version=0,
        )
        addr_1 = bits.to_bitcoin_address(
            bits.script_hash(redeem_script), addr_type="p2sh", network="regtest"
        )
        addr_1_from_keys = [
            bits.wif_encode(
                key,
                addr_type="p2sh-p2wsh",
                network="regtest",
                data=witness_script,
            )
            for key in keys[:m]
        ]

        tx_ = bits.tx.send_tx(
            addr_0,
            addr_1,
            from_keys=[wif_key_0],
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )

        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
        bits.rpc.rpc_method("sendrawtransaction", tx_.hex())
        bits.integrations.mine_block(b"")

        # test spenditure p2sh-p2wsh
        tx_ = bits.tx.send_tx(
            addr_1,
            addr_0,
            from_keys=addr_1_from_keys,
            sighash_flag=bits.script.constants.SIGHASH_ALL,
            miner_fee=MINER_FEE,
        )
        ret = bits.rpc.rpc_method("testmempoolaccept", f'["{tx_.hex()}"]')
        assert ret[0]["allowed"] == True, ret
