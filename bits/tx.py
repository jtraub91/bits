"""
Utilities for transactions

https://developer.bitcoin.org/reference/transactions.html
"""
from hashlib import sha256

from bits.btypes import compact_size_uint, Bytes
from bits.script import Script


class OutPoint(Bytes):
    def __init__(self, txid: bytes, index: int):
        self.txid = txid  # internal byte order ?
        self.index = index

    def raw(self) -> bytes:
        return self.txid + self.index.to_bytes(4, "little")

class TxIn(Bytes):
    def __init__(
        self,
        prev_outpoint: OutPoint,
        script_sig: Script,
        sequence: bytes = b"\xff\xff\xff\xff",
    ):
        self.prev_outpoint = prev_outpoint
        self.script_sig = script_sig
        self.sequence = sequence

    def raw(self) -> bytes:
        raw_txin = (
            self.prev_outpoint.raw()
            + compact_size_uint(len(self.script_sig))
            + self.script_sig.raw()
            + self.sequence
        )
        return raw_txin


class TxOut(Bytes):
    def __init__(self, value: int, script_pubkey: Script):
        self.value = value
        self.script_pubkey = script_pubkey

    def raw(self) -> bytes:
        raw_txout = (
            self.value.to_bytes(8, "little", signed=True)
            + compact_size_uint(len(self.script_pubkey))
            + self.script_pubkey.raw()
        )
        return raw_txout


class Tx(Bytes):
    """
    Bitcoin transaction
    """

    version = 1

    def __init__(self, inputs: list[TxIn], outputs: list[TxOut], locktime=0):
        self.inputs: list[TxIn] = inputs
        self.outputs: list[TxOut] = outputs
        self.locktime: bytes = locktime.to_bytes(4, "little")


    def raw(self) -> bytes:
        """
        Serialized transaction in raw bytes format
        """
        raw_tx = self.version.to_bytes(4, "little", signed=True) + compact_size_uint(
            len(self.inputs)
        )
        for txin in self.inputs:
            raw_tx += txin.raw()
        raw_tx += compact_size_uint(len(self.outputs))
        for txout in self.outputs:
            raw_tx += txout.raw()
        raw_tx += self.locktime
        return raw_tx
