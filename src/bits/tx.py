"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
import logging
import typing

import bits.keys
import bits.script.constants

UINT32_MAX = 2**32 - 1

log = logging.getLogger(__name__)


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
    return (
        prev_outpoint + bits.compact_size_uint(len(script_sig)) + script_sig + sequence
    )


def txin_deser(txin_: bytes) -> typing.Tuple[dict, bytes]:
    txid_ = txin_[:32]
    vout = txin_[32:36]
    scriptsig_len, txin_prime = bits.parse_compact_size_uint(txin_[36:])
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
        + bits.compact_size_uint(len(script_pubkey))
        + script_pubkey
    )


def txout_deser(txout_: bytes) -> typing.Tuple[dict, bytes]:
    value = txout_[:8]
    scriptpubkey_len, txout_prime = bits.parse_compact_size_uint(txout_[8:])
    scriptpubkey = txout_prime[:scriptpubkey_len]
    txout_ = txout_prime[scriptpubkey_len:]
    return {
        "value": int.from_bytes(value, "little"),
        "scriptpubkey": scriptpubkey.hex(),
    }, txout_


def tx(
    txins: typing.List[bytes],
    txouts: typing.List[bytes],
    version: int = 1,
    locktime: int = 0,
    script_witnesses: typing.List[bytes] = [],
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


def tx_deser(tx_: bytes) -> typing.Tuple[dict, bytes]:
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
        txin_, tx_prime = txin_deser(tx_prime)
        txins.append(txin_)
    deserialized_tx["txins"] = txins

    number_of_outputs, tx_prime = bits.parse_compact_size_uint(tx_prime)
    txouts = []
    for _ in range(number_of_outputs):
        txout_, tx_prime = txout_deser(tx_prime)
        txouts.append(txout_)
    deserialized_tx["txouts"] = txouts

    if is_segwit:
        deserialized_tx["witnesses"] = []
        for i in range(len(txins)):
            witness_script, tx_prime = bits.script.decode_script(tx_prime, witness=True)
            deserialized_tx["witnesses"].append(witness_script)

    locktime = tx_prime[:4]
    deserialized_tx["locktime"] = int.from_bytes(locktime, "little")

    tx_prime = tx_prime[4:]
    return deserialized_tx, tx_prime


def txid(tx_: bytes) -> str:
    return bits.hash256(tx_)[::-1].hex()  # rpc byte order


def coinbase_txin(
    coinbase_script: bytes,
    sequence: bytes = b"\xff\xff\xff\xff",
    block_height: typing.Optional[int] = None,
) -> bytes:
    """
    Create coinbase txin
    Args:
        coinbase_script: bytes, arbitrary data not exceeding 100 bytes
        block_height: bytes, block height of this block in script language
            (now required per BIP34)
    """
    if block_height is not None:
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
    block_reward: typing.Optional[int] = None,
    block_height: typing.Optional[int] = None,
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
        raise ValueError(f"unrecognized network: {network}")
    return tx(
        [coinbase_txin(coinbase_script, block_height=block_height)],
        [txout(block_reward, script_pubkey)],
    )


def send_tx(
    from_: bytes,
    to_: bytes,
    from_keys: typing.List[bytes] = [],
    sighash_flag: typing.Optional[int] = None,
    miner_fee: int = 1000,
    version: int = 1,
    locktime: int = 0,
) -> bytes:
    """
    Create raw transaction which sends all funds from addr to addr
    Uses rpc bitcoind node for utxo discovery
    Args:
        from_: bytes, send from this address
        to_: bytes, send to this address
        from_keys: List[bytes], unlocking WIF key(s) corresponding to from_ addr
            Using this cause signature operations to occur.
            Omit to return the unsigned transaction
        sighash_flag: Optional[int], sighash_flag, required if providing from_keys
        miner_fee: int, amount (in satoshis) to include as miner fee
        version: int, transaction version
        locktime: int, transaction locktime
    """
    # scan for utxo for the from_ descriptor
    if bits.is_point(from_):
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

    # if from_keys, validate and decode
    if from_keys:
        if sighash_flag is None:
            raise ValueError(
                "from_keys provided for signing but sighash_flag not specified"
            )

        decoded_from_keys = [
            bits.wif_decode(from_key, return_dict=True) for from_key in from_keys
        ]
        keys = [bytes.fromhex(decoded_key["key"]) for decoded_key in decoded_from_keys]

        addr_types = list(map(lambda key: key["addr_type"], decoded_from_keys))
        datums = list(map(lambda key: key["data"], decoded_from_keys))
        assert all(
            addr_type == addr_types[0] for addr_type in addr_types
        ), "from_keys must all have same addr_type"
        assert all(
            datum == datums[0] for datum in datums
        ), "from_keys must have same data appenditure"

        if addr_types[0] in ["p2pk", "p2pkh", "p2wpkh", "p2sh-p2wpkh"]:
            if len(from_keys) > 1:
                raise ValueError(f"more than 1 from_key provided for {addr_types[0]}")
        elif addr_types[0] in ["multisig", "p2sh", "p2wsh", "p2sh-p2wsh"]:
            redeem_script = bytes.fromhex(datums[0])

    txins = []
    for utxo in from_txoutset["unspents"]:
        txid = bytes.fromhex(utxo["txid"])[::-1]
        from_scriptpubkey = bytes.fromhex(utxo["scriptPubKey"])
        if from_keys:
            if addr_types[0] in ["p2pk", "p2pkh", "multisig"]:
                from_scriptsig = from_scriptpubkey
            elif from_keys and addr_types[0] in ["p2sh"]:
                from_scriptsig = redeem_script
            elif from_keys and addr_types[0] in ["p2sh-p2wpkh"]:
                from_scriptsig = bits.script.script(
                    [
                        bits.script.p2wpkh_script_pubkey(
                            bits.hash160(bits.keys.pub(keys[0], compressed=True)),
                            witness_version=0,
                        ).hex()
                    ]
                )
            elif from_keys and addr_types[0] in ["p2sh-p2wsh"]:
                from_scriptsig = bits.script.script(
                    [
                        bits.script.p2wsh_script_pubkey(
                            bits.witness_script_hash(redeem_script), witness_version=0
                        ).hex()
                    ]
                )
            else:
                # p2wpkh / p2wsh
                from_scriptsig = b""
        vout = utxo["vout"]
        txins.append(txin(outpoint(txid, vout), from_scriptsig))
    total_amount = int(from_txoutset["total_amount"] * 1e8)

    to_scriptpubkey = bits.script.scriptpubkey(to_)
    txouts = [txout(total_amount - miner_fee, to_scriptpubkey)]

    tx_ = tx(txins, txouts, version=version, locktime=locktime)

    if from_keys:
        # sign
        if addr_types[0] in ["p2wpkh", "p2wsh", "p2sh-p2wpkh", "p2sh-p2wsh"]:
            if addr_types[0] in ["p2wpkh", "p2sh-p2wpkh"]:
                pk = bits.keys.pub(keys[0], compressed=True)
                pkh = bits.hash160(pk)
                scriptcode = bits.script.script(
                    [
                        bits.script.script(
                            [
                                "OP_DUP",
                                "OP_HASH160",
                                pkh.hex(),
                                "OP_EQUALVERIFY",
                                "OP_CHECKSIG",
                            ]
                        ).hex()
                    ]
                )
            elif addr_types[0] in ["p2wsh", "p2sh-p2wsh"]:
                scriptcode = len(redeem_script).to_bytes(1, "big") + redeem_script
                # see test_bip143:test_p2sh_p2wsh ^^ regarding non-use of OP_PUSHDATA
                # but, how to serialize when len(redeem_script) > 255 ?
            msgs = [
                bits.bips.bip143.witness_message(
                    txins,
                    utxo["vout"],
                    int(utxo["amount"] * 1e8),
                    scriptcode,
                    txouts,
                    sighash_flag=sighash_flag,
                )
                for utxo in from_txoutset["unspents"]
            ]
            signatures = [
                [
                    bits.sig(key, msg, sighash_flag=sighash_flag, msg_preimage=True)
                    for key in keys
                ]
                for msg in msgs
            ]
        else:
            # p2sh / p2pk / p2pkh / multisig
            msg = tx_
            signatures = [bits.sig(key, msg, sighash_flag=sighash_flag) for key in keys]

        # form final scriptsig / witnesses
        if addr_types[0] == "p2pk":
            from_scriptsig = bits.script.script([signatures[0].hex()])
            from_witnesses = []
        elif addr_types[0] == "multisig":
            from_scriptsig = bits.script.script(
                ["OP_0"] + [signature.hex() for signature in signatures]
            )
            from_witnesses = []
        elif addr_types[0] == "p2pkh":
            compressed = True if datums[0] else False
            from_scriptsig = bits.script.script(
                [
                    signatures[0].hex(),
                    bits.keys.pub(keys[0], compressed=compressed).hex(),
                ]
            )
            from_witnesses = []
        elif addr_types[0] in ["p2wpkh", "p2sh-p2wpkh"]:
            from_witnesses = [
                bits.script.script(
                    [
                        signatures[i][0].hex(),
                        bits.keys.pub(keys[0], compressed=True).hex(),
                    ],
                    witness=True,
                )
                for i in range(len(txins))
            ]
        elif addr_types[0] in ["p2sh", "p2wsh", "p2sh-p2wsh"]:
            decoded_script = bits.script.decode_script(redeem_script)
            if decoded_script[-1] == "OP_CHECKMULTISIG":
                script_args = ["OP_0"]
            else:
                script_args = []

            if addr_types[0] == "p2sh":
                script_args += [signature.hex() for signature in signatures]
                script_args += [redeem_script.hex()]
                from_scriptsig = bits.script.script(script_args)
                from_witnesses = []
            elif addr_types[0] in ["p2wsh", "p2sh-p2wsh"]:
                from_witnesses = [
                    bits.script.script(
                        script_args
                        + [signature.hex() for signature in signatures[i]]
                        + [redeem_script.hex()],
                        witness=True,
                    )
                    for i in range(len(txins))
                ]

        txins = []
        for utxo in from_txoutset["unspents"]:
            txid = bytes.fromhex(utxo["txid"])[::-1]
            vout = utxo["vout"]
            txins.append(txin(outpoint(txid, vout), from_scriptsig))
        tx_ = tx(
            txins,
            txouts,
            script_witnesses=from_witnesses,
            version=version,
            locktime=locktime,
        )
    return tx_
