"""
https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#example
"""
from bits.bips.bip143 import witness_digest
from bits.bips.bip143 import witness_message
from bits.script.constants import SIGHASH_ALL
from bits.script.utils import p2pk_script_sig
from bits.script.utils import script
from bits.tx import outpoint
from bits.tx import tx
from bits.tx import tx_deser
from bits.tx import txin
from bits.tx import txout
from bits.utils import hash256
from bits.utils import sig


def test_p2wpkh():
    """
    Start with unsigned transaction in example
    deserialize
    """
    unsigned_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
    deserialized_tx, _ = tx_deser(bytes.fromhex(unsigned_tx))

    """
    The first input comes from an ordinary P2PK:
        scriptPubKey : 2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac value: 6.25
        private key  : bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866
    
    The second input comes from a P2WPKH witness program:
        scriptPubKey : 00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1, value: 6
        private key  : 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
        public key   : 025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357
    """

    txins = [
        txin(
            outpoint(bytes.fromhex(ti["txid"]), ti["vout"]),
            b"",
            sequence=bytes.fromhex(ti["sequence"]),
        )
        for ti in deserialized_tx["txins"]
    ]
    txouts = [
        txout(to["value"], bytes.fromhex(to["scriptpubkey"]))
        for to in deserialized_tx["txouts"]
    ]

    msg = witness_message(
        txins,
        1,
        int(6e8),
        bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        sighash_flag=SIGHASH_ALL,
    )

    expected_hash_preimage = bytes.fromhex(
        "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000"
    )
    assert msg.hex() == expected_hash_preimage.hex(), "hash preimage mismatch"

    sighash = witness_digest(msg)
    expected_sighash = bytes.fromhex(
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )
    assert sighash.hex() == expected_sighash.hex(), "sighash data mismatch"

    input_2_private_key = bytes.fromhex(
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
    )
    witness_signature = sig(
        input_2_private_key,
        msg,
        sighash_flag=SIGHASH_ALL,
    )

    input_1_scriptpubkey = bytes.fromhex(
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
    )
    txins = [
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][0]["txid"]),
                deserialized_tx["txins"][0]["vout"],
            ),
            input_1_scriptpubkey,
            sequence=bytes.fromhex(deserialized_tx["txins"][0]["sequence"]),
        ),
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][1]["txid"]),
                deserialized_tx["txins"][1]["vout"],
            ),
            b"",
            sequence=bytes.fromhex(deserialized_tx["txins"][1]["sequence"]),
        ),
    ]
    tx_ = tx(
        txins,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
    )
    input_1_private_key = bytes.fromhex(
        "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866"
    )
    input_1_signature = sig(
        input_1_private_key,
        tx_,
        sighash_flag=SIGHASH_ALL,
    )
    input_1_scriptsig = p2pk_script_sig(input_1_signature)
    txins = [
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][0]["txid"]),
                deserialized_tx["txins"][0]["vout"],
            ),
            input_1_scriptsig,
            sequence=bytes.fromhex(deserialized_tx["txins"][0]["sequence"]),
        ),
        txin(
            outpoint(
                bytes.fromhex(deserialized_tx["txins"][1]["txid"]),
                deserialized_tx["txins"][1]["vout"],
            ),
            b"",
            sequence=bytes.fromhex(deserialized_tx["txins"][1]["sequence"]),
        ),
    ]
    input_2_pubkey = bytes.fromhex(
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
    )
    input_2_witness_script = b"\x02" + script(
        [
            witness_signature.hex(),
            input_2_pubkey.hex(),
        ]
    )
    tx_ = tx(
        txins,
        txouts,
        version=deserialized_tx["version"],
        locktime=deserialized_tx["locktime"],
        script_witnesses=[
            b"\x00",
            input_2_witness_script,
        ],
    )
    expected_signed_transaction = bytes.fromhex(
        "01000000"
        + "00"
        + "01"
        + "02"
        + "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
        + "00000000"
        + format(len(input_1_scriptsig), "02x")
        + input_1_scriptsig.hex()
        + "eeffffff"
        + "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"
        + "01000000"
        + "00"
        + "ffffffff"
        + "02"
        + "202cb20600000000"
        + "1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
        + "9093510d00000000"
        + "1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
        + "00"
        + "02"
        + format(len(witness_signature), "02x")
        + witness_signature.hex()
        + "21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
        + "11000000"
    )
    assert tx_.hex() == expected_signed_transaction.hex()


# def test_p2sh_p2wpkh():
#     return


# def test_p2wsh():
#     return


# def test_p2sh_p2wsh():
#     return


# def test_no_find_and_delete():
#     return
