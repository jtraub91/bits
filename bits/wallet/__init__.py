import logging
import os

import bits.db as db
from bits.utils import to_bitcoin_address
from bits.wallet.hd import HD

__all__ = ["HD", "Wallet"]

log = logging.getLogger("wallet")


class Wallet:
    """
    Top level wallet class abstraction
    Manage keys, balance, database, etc.
    """

    def __init__(self):
        if not db.detect_schema():
            db.init_schema()
        self._dbconnection = db.connection
        self._dbcursor = db.cursor
        self.name = None
        self.type = None

    def load(self, name: str, wallet_type: str):
        """
        Load wallet, i.e.
        Store loaded wallet as row in db
        """
        res = self._dbcursor.execute("SELECT * FROM wallet").fetchall()
        assert len(res) <= 1
        if len(res) == 1:
            row_name, row_type = res[0]
            self._dbcursor.execute("DELETE FROM wallet WHERE name = ?", (row_name,))
            self._dbconnection.commit()
        self._dbcursor.execute(
            "INSERT INTO wallet (name, type) VALUES (?, ?)", (name, wallet_type)
        )
        self._dbconnection.commit()
        self.name = name
        self.type = wallet_type

    def list_addrs(self):
        if self.type == "jbok":
            wallet_keys = os.listdir(f".bits/wallets/{self.type}/{self.name}")
            wallet_public_pems = [
                pem for pem in wallet_keys if pem.startswith("public")
            ]
            addrs = [
                to_bitcoin_address(wpp, network="mainnet") for wpp in wallet_public_pems
            ]
            return addrs

    def get_balance(self):
        return
