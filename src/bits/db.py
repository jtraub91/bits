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
            CREATE INDEX blockhashindex ON block(blockheight, blockheaderhash);
            CREATE INDEX blockheaderindex ON block(blockheaderhash, prev_blockheaderhash, merkle_root_hash, nTime, nBits);
            CREATE INDEX blockdataindex ON block(blockheight, blockheaderhash, datafile, datafile_offset);
        """
        )
        self._curs.execute(
            """
            CREATE TABLE utxo(
                id INTEGER PRIMARY KEY,
                blockheaderhash TEXT,
                txid TEXT,
                vout INTEGER

            )
        """
        )


class Block:
    height: int
