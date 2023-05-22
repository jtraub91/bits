"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
import logging
import typing

import bits.constants
import bits.keys
import bits.script.constants
from bits.bips import bip143
from bits.bips import bip173

UINT32_MAX = 2**32 - 1

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


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
    txid_ = txin_[:32]  # TODO: switch to rpc byte order
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


def tx_deser(tx_: bytes, include_raw: bool = False) -> typing.Tuple[dict, bytes]:
    """
    Deserialize tx data
    Args:
        tx_: bytes, tx data
        include_raw: bool, if True, include raw hex transaction in dict
    Returns:
        tuple, (deserialized tx, leftove )
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
    tx_ = tx_.split(tx_prime)[0] if tx_prime else tx_

    # re-serialize without witness for txid, and hash
    # TODO: Tx class to maybe calculate this more efficiently?
    tx_dict = (
        {
            "txid": bits.hash256(
                tx(
                    [
                        txin(
                            outpoint(bytes.fromhex(ti["txid"]), ti["vout"]),
                            bytes.fromhex(ti["scriptsig"]),
                        )
                        for ti in deserialized_tx["txins"]
                    ],
                    [
                        txout(to["value"], bytes.fromhex(to["scriptpubkey"]))
                        for to in deserialized_tx["txouts"]
                    ],
                    version=deserialized_tx["version"],
                    locktime=deserialized_tx["locktime"],
                )
            ).hex()
        }
        if is_segwit
        else {"txid": bits.hash256(tx_).hex()}
    )
    tx_dict["wtxid"] = bits.hash256(tx_).hex()
    if include_raw:
        tx_dict["raw"] = tx_.hex()
    tx_dict.update(deserialized_tx)
    return tx_dict, tx_prime


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
    regtest: bool = False,
    witness_merkle_root_hash: typing.Optional[bytes] = None,
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
        script_witnesses=[
            bits.script.script(
                [bits.constants.WITNESS_RESERVED_VALUE.hex()], witness=True
            )
        ]
        if witness_merkle_root_hash
        else [],
    )


def send_tx(
    sender_addr: bytes,
    recipient_addr: bytes,
    change_addr: typing.Optional[bytes] = None,
    sender_keys: typing.List[bytes] = [],
    sighash_flag: typing.Optional[int] = None,
    send_fraction: float = 1.0,
    miner_fee: int = 1000,
    version: int = 1,
    locktime: int = 0,
    rpc_url: str = "",
    rpc_datadir: str = "",
    rpc_user: str = "",
    rpc_password: str = "",
) -> bytes:
    """
    Create raw transaction which sends funds from addr to addr, with optional change address.
    Depends on configured Bitcoin Core RPC node for UTXO discovery.
    Args:
        sender_addr: bytes, send from this address
        recipient_addr: bytes, send to this address
        change_addr: Optional[bytes], send change to this address
        sender_keys: List[bytes], unlocking WIF key(s) corresponding to sender_addr
            Using this causes signature operations to occur.
            Omit to return the unsigned transaction
        sighash_flag: Optional[int], sighash_flag, required if providing sender_keys
        send_fraction: float, fraction of UTXO value to send to recipient, leftover is
            sent to change_addr if present, else returned to sender_addr
        miner_fee: int, amount (in satoshis) to include as miner fee
        version: int, transaction version
        locktime: int, transaction locktime
    """
    rpc_kwargs = {
        "rpc_url": rpc_url,
        "rpc_datadir": rpc_datadir,
        "rpc_user": rpc_user,
        "rpc_password": rpc_password,
    }
    # scan for utxo for the sender_addr descriptor
    if bits.is_point(sender_addr):
        sender_txoutset = bits.rpc.rpc_method(
            "scantxoutset", "start", f'["pk({sender_addr.hex()})"]', **rpc_kwargs
        )
    elif bits.base58.is_base58check(sender_addr) or bip173.is_segwit_addr(sender_addr):
        sender_txoutset = bits.rpc.rpc_method(
            "scantxoutset",
            "start",
            f'["addr({sender_addr.decode("utf8")})"]',
            **rpc_kwargs,
        )
    else:
        # raw scriptpubkey
        sender_txoutset = bits.rpc.rpc_method(
            "scantxoutset", "start", f'["raw({sender_addr.hex()})"]', **rpc_kwargs
        )

    # if sender_keys, validate and decode
    if sender_keys:
        if sighash_flag is None:
            raise ValueError(
                "sender_keys provided for signing but sighash_flag not specified"
            )

        decoded_sender_keys = [
            bits.wif_decode(sender_key, return_dict=True) for sender_key in sender_keys
        ]
        keys = [
            bytes.fromhex(decoded_key["key"]) for decoded_key in decoded_sender_keys
        ]

        addr_types = list(map(lambda key: key["addr_type"], decoded_sender_keys))
        datums = list(map(lambda key: key["data"], decoded_sender_keys))
        assert all(
            addr_type == addr_types[0] for addr_type in addr_types
        ), "sender_keys must all have same addr_type"
        assert all(
            datum == datums[0] for datum in datums
        ), "sender_keys must have same data appenditure"

        if addr_types[0] in ["p2pk", "p2pkh", "p2wpkh", "p2sh-p2wpkh"]:
            if len(sender_keys) > 1:
                raise ValueError(f"more than 1 sender_key provided for {addr_types[0]}")
        elif addr_types[0] in ["multisig", "p2sh", "p2wsh", "p2sh-p2wsh"]:
            redeem_script = bytes.fromhex(datums[0])

    total_available = int(sender_txoutset["total_amount"] * 1e8)
    amount_to_send = int(send_fraction * total_available)
    total_amount = 0
    txins = []
    for utxo in sender_txoutset["unspents"]:
        amount = utxo["amount"] * 1e8
        txid = bytes.fromhex(utxo["txid"])[::-1]
        vout = utxo["vout"]
        sender_scriptsig = b""
        if sender_keys:
            if addr_types[0] in ["p2pk", "p2pkh", "multisig"]:
                sender_scriptsig = bytes.fromhex(utxo["scriptPubKey"])
            elif sender_keys and addr_types[0] in ["p2sh"]:
                sender_scriptsig = redeem_script
            elif sender_keys and addr_types[0] in ["p2sh-p2wpkh"]:
                sender_scriptsig = bits.script.script(
                    [
                        bits.script.p2wpkh_script_pubkey(
                            bits.hash160(bits.keys.pub(keys[0], compressed=True)),
                            witness_version=0,
                        ).hex()
                    ]
                )
            elif sender_keys and addr_types[0] in ["p2sh-p2wsh"]:
                sender_scriptsig = bits.script.script(
                    [
                        bits.script.p2wsh_script_pubkey(
                            bits.witness_script_hash(redeem_script), witness_version=0
                        ).hex()
                    ]
                )
            else:
                # p2wpkh / p2wsh
                sender_scriptsig = b""
        txins.append(txin(outpoint(txid, vout), sender_scriptsig))
        total_amount += amount
        if total_amount >= amount_to_send:
            break

    recipient_scriptpubkey = bits.script.scriptpubkey(recipient_addr)
    change_scriptpubkey = (
        bits.script.scriptpubkey(change_addr)
        if change_addr
        else bits.script.scriptpubkey(sender_addr)
    )
    txouts = [
        txout(int(amount_to_send - miner_fee), recipient_scriptpubkey),
    ]
    if int(total_amount - amount_to_send) >= 1000:  # TODO: > dust limit
        txouts.append(txout(int(total_amount - amount_to_send), change_scriptpubkey))

    tx_ = tx(txins, txouts, version=version, locktime=locktime)

    if sender_keys:
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
                bip143.witness_message(
                    txins,
                    utxo["vout"],
                    int(utxo["amount"] * 1e8),
                    scriptcode,
                    txouts,
                    sighash_flag=sighash_flag,
                )
                for utxo in sender_txoutset["unspents"]
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
            sender_scriptsig = bits.script.script([signatures[0].hex()])
            sender_witnesses = []
        elif addr_types[0] == "multisig":
            sender_scriptsig = bits.script.script(
                ["OP_0"] + [signature.hex() for signature in signatures]
            )
            sender_witnesses = []
        elif addr_types[0] == "p2pkh":
            compressed = True if datums[0] else False
            sender_scriptsig = bits.script.script(
                [
                    signatures[0].hex(),
                    bits.keys.pub(keys[0], compressed=compressed).hex(),
                ]
            )
            sender_witnesses = []
        elif addr_types[0] in ["p2wpkh", "p2sh-p2wpkh"]:
            sender_witnesses = [
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
                sender_scriptsig = bits.script.script(script_args)
                sender_witnesses = []
            elif addr_types[0] in ["p2wsh", "p2sh-p2wsh"]:
                sender_witnesses = [
                    bits.script.script(
                        script_args
                        + [signature.hex() for signature in signatures[i]]
                        + [redeem_script.hex()],
                        witness=True,
                    )
                    for i in range(len(txins))
                ]

        txins_prime = []
        for txi in txins:
            txin_deserialized, _ = txin_deser(txi)
            txid = bytes.fromhex(txin_deserialized["txid"])
            vout = txin_deserialized["vout"]
            txins_prime.append(txin(outpoint(txid, vout), sender_scriptsig))
        tx_ = tx(
            txins_prime,
            txouts,
            script_witnesses=sender_witnesses,
            version=version,
            locktime=locktime,
        )
    return tx_
