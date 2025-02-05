import sqlite3


class Db:
    def __init__(self, db_filepath: str):
        self._conn = sqlite3.connect(db_filepath)
        self._curs = self._conn.cursor()

    def create_tables(self):
        self._curs.execute(
            """
            CREATE TABLE block(
                id INTEGER PRIMARY KEY,
                blockheight INTEGER UNIQUE, 
                blockheaderhash TEXT,
                version INTEGER,
                prev_blockheaderhash TEXT,
                merkle_root_hash TEXT,
                nTime INTEGER,
                nBits TEXT,
                nNonce INTEGER,

                datafile TEXT,
                datafile_offset INTEGER
            );
            CREATE INDEX block_index ON block(blockheight, blockheaderhash);
        """
        )
        self._curs.execute(
            """
            CREATE TABLE utxo(
                id INTEGER PRIMARY KEY,
                blockheaderhash TEXT,
                txid TEXT,
                vout INTEGER
            );
            CREATE INDEX utxo_index ON utxo(blockheaderhash, txid);
        """
        )
        self._curs.execute(
            """
            CREATE TABLE peer(
                id INTEGER PRIMARY KEY,
                data TEXT
            )
        """
        )

    def get_peer(self, id_: int):
        query = "SELECT * from peer WHERE id={id_}"
