import json
import logging
import sqlite3
from typing import List
from typing import Optional
from typing import Union

log = logging.getLogger(__name__)


class Db:
    def __init__(self, db_filepath: str):
        self._conn = sqlite3.connect(db_filepath, check_same_thread=False)
        self._curs = self._conn.cursor()
        # if tables don't exist, create them
        for table in ["block", "utxoset", "peer"]:
            res = self._curs.execute(
                f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}';"
            )
            if not res.fetchone():
                self.create_tables()
                break

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
        """
        )
        self._conn.commit()
        self._curs.execute("CREATE INDEX blockheight_index ON block(blockheight);")
        self._conn.commit()
        self._curs.execute(
            "CREATE INDEX blockheaderhash_index ON block(blockheaderhash);"
        )
        self._conn.commit()
        self._curs.execute(
            """
            CREATE TABLE utxoset(
                id INTEGER PRIMARY KEY,
                blockheaderhash TEXT,
                txid TEXT,
                vout INTEGER
            );
        """
        )
        self._conn.commit()
        self._curs.execute("CREATE INDEX utxo_txid_vout_index ON utxoset(txid, vout);")
        self._conn.commit()
        self._curs.execute(
            "CREATE INDEX utxo_blockheaderhash_index ON utxoset(blockheaderhash);"
        )
        self._conn.commit()
        self._curs.execute(
            """
            CREATE TABLE peer(
                id INTEGER PRIMARY KEY,
                host TEXT,
                port INTEGER,
                data TEXT
            );
        """
        )
        self._conn.commit()
        self._curs.execute(
            """
            CREATE TABLE node_state(
                id INTEGER PRIMARY KEY,
                network TEXT,
                ibd BOOLEAN,
                progress REAL,
                running BOOLEAN,
                difficulty REAL,
                height INTEGER,
                bestblockheaderhash TEXT,
                time INTEGER,
                mediantime INTEGER
            );
        """
        )
        self._conn.commit()

    def delete_block(self, blockheaderhash: str):
        self._curs.execute(
            f"DELETE FROM block WHERE blockheaderhash='{blockheaderhash}';"
        )
        self._conn.commit()

    def save_block(
        self,
        blockheight: int,
        blockheaderhash: str,
        version: int,
        prev_blockheaderhash: str,
        merkle_root_hash: str,
        nTime: int,
        nBits: str,
        nNonce: int,
        datafile: str,
        datafile_offset: int,
    ):
        cmd = f"""
            INSERT INTO block (
                blockheight,
                blockheaderhash,
                version,
                prev_blockheaderhash,
                merkle_root_hash,
                nTime,
                nBits,
                nNonce,
                datafile,
                datafile_offset
            ) VALUES (
                {blockheight},
                '{blockheaderhash}',
                {version},
                '{prev_blockheaderhash}',
                '{merkle_root_hash}',
                {nTime},
                '{nBits}',
                {nNonce},
                '{datafile}',
                {datafile_offset}
            );
        """
        self._curs.execute(cmd)
        self._conn.commit()

    def get_blockchain_height(self) -> Union[int | None]:
        res = self._curs.execute(
            "SELECT blockheight FROM block ORDER BY blockheight DESC LIMIT 1;"
        )
        result = res.fetchone()
        return result[0] if result else None

    def count_blocks(self) -> int:
        res = self._curs.execute("SELECT COUNT(*) FROM block;")
        return int(res.fetchone()[0])

    def get_block(
        self, blockheight: int = None, blockheaderhash: str = None
    ) -> Union[dict, None]:
        """
        Get the block data from index db, i.e. header data, meta data

        NOTE: only 1 of blockheight or blockheaderhash can be provided as argument,
            but not both, or else ValueError will be thrown

        Args:
            blockheight: int, blockheight
            blockheaderhash: str, blockheaderhash
        Returns:
            dict, block index db data, or
            None, if not found
        """
        if blockheight is not None and blockheaderhash is not None:
            raise ValueError(
                "both blockheight and blockheaderhash should not be specified"
            )
        elif blockheight is None and blockheaderhash is None:
            raise ValueError("blockheight or blockheaderhash must be provided")
        elif blockheight is not None:
            arg = f"blockheight={blockheight}"
            res = self._curs.execute(
                f"SELECT * FROM block WHERE blockheight='{blockheight}';"
            )
        else:
            # blockheaderhash is not None
            arg = f"blockheaderhash={blockheaderhash}"
            res = self._curs.execute(
                f"SELECT * FROM block WHERE blockheaderhash='{blockheaderhash}';"
            )

        result = res.fetchone()
        return (
            {
                "blockheight": int(result[1]),
                "blockheaderhash": result[2],
                "version": int(result[3]),
                "prev_blockheaderhash": result[4],
                "merkle_root_hash": result[5],
                "nTime": int(result[6]),
                "nBits": result[7],
                "nNonce": int(result[8]),
                "datafile": result[9],
                "datafile_offset": int(result[10]),
            }
            if result
            else None
        )

    def remove_from_utxoset(
        self, blockheaderhash: str, txid: str, vout: int, commit=True
    ):
        self._curs.execute(
            f"DELETE FROM utxoset WHERE blockheaderhash='{blockheaderhash}' AND txid='{txid}' AND vout='{vout}';"
        )
        if commit:
            self._conn.commit()

    def add_to_utxoset(self, blockheaderhash: str, txid: str, vout: int, commit=True):
        self._curs.execute(
            f"INSERT INTO utxoset (blockheaderhash, txid, vout) VALUES ('{blockheaderhash}', '{txid}', {vout});"
        )
        if commit:
            self._conn.commit()

    def get_block_utxos(self, blockheaderhash: str) -> List[dict]:
        res = self._curs.execute(
            f"SELECT txid, vout FROM utxoset WHERE blockheaderhash='{blockheaderhash}';"
        )
        results = res.fetchall()
        return [{"txid": result[0], "vout": result[1]} for result in results]

    def find_blockheaderhash_for_utxo(self, txid: str, vout: int) -> Union[str, None]:
        res = self._curs.execute(
            f"SELECT blockheaderhash FROM utxoset WHERE txid='{txid}' AND vout={vout};"
        )
        result = res.fetchone()
        return result[0] if result else None

    def save_peer(self, host: str, port: int) -> int:
        self._curs.execute(f"INSERT INTO peer (host, port) VALUES ('{host}', {port});")
        self._conn.commit()
        res = self._curs.execute(
            f"SELECT id FROM peer WHERE host='{host}' and port='{port}';"
        )
        return res.fetchone()[0]

    def save_peer_data(self, peer_id: int, data: dict):
        res = self._curs.execute(f"SELECT data from peer WHERE id='{peer_id}';")
        peer_data = res.fetchone()[0]
        peer_data = json.loads(peer_data) if peer_data else {}
        peer_data.update(data)
        peer_data = json.dumps(peer_data)
        self._curs.execute(f"UPDATE peer SET data='{peer_data}' WHERE id='{peer_id}';")
        self._conn.commit()

    def get_peer_data(
        self, peer_id: int, key: Optional[str] = None
    ) -> Union[None, str, list, dict, int, float]:
        res = self._curs.execute(f"SELECT data FROM peer WHERE id='{peer_id}';")
        result = res.fetchone()
        if result:
            data = json.loads(result[0]) if result[0] else {}
        else:
            data = None
        if key and result:
            return data.get(key)
        return data

    def last_non_min_diff_in_diff_adj_period(self) -> Union[str, None]:
        """
        Find the last non minimum difficulty for a block in this difficulty adjustment period

        Used for testnet only, supposed to snap back to this difficulty, the block
            after artificially setting the difficulty to 1
            (which is allowed when no block is mined in >= 20 min)
        Returns:
            str, last non minimum difficulty in this period, or
            None, if no non-minimum difficulty is found
        """
        current_blockheight = self.get_blockchain_height()
        res = self._curs.execute(
            f"SELECT nBits FROM block WHERE nBits!='1d00ffff' AND blockheight>={current_blockheight - (current_blockheight % 2016)} AND blockheight<={current_blockheight} ORDER BY blockheight DESC;"
        )
        result = res.fetchone()
        return result[0] if result else None

    def save_node_state(
        self,
        network: Optional[str] = None,
        ibd: Optional[bool] = None,
        progress: Optional[float] = None,
        running: Optional[bool] = None,
        difficulty: Optional[float] = None,
        height: Optional[int] = None,
        bestblockheaderhash: Optional[str] = None,
        time: Optional[int] = None,
        mediantime: Optional[int] = None,
        commit: bool = True,
    ):
        if not self.get_node_state():
            self._curs.execute("INSERT INTO node_state (id) VALUES (1);")
            self._conn.commit()
        res = self._curs.execute(f"SELECT * from node_state;")
        results = res.fetchall()
        assert len(results) == 1, "multiple rows in node_state table"
        result = results[0]
        assert result[0] == 1, "node state row id != 1"
        set_statement = ""
        if network is not None:
            set_statement += f"network='{network}', "
        if ibd is not None:
            set_statement += "ibd='TRUE', " if ibd else "ibd='FALSE', "
        if progress is not None:
            set_statement += f"progress='{progress}', "
        if running is not None:
            set_statement += "running='TRUE', " if running else "running='FALSE', "
        if difficulty is not None:
            set_statement += f"difficulty='{difficulty}', "
        if height is not None:
            set_statement += f"height={height}, "
        if bestblockheaderhash is not None:
            set_statement += f"bestblockheaderhash='{bestblockheaderhash}', "
        if time is not None:
            set_statement += f"time={time}, "
        if mediantime is not None:
            set_statement += f"mediantime={mediantime}, "
        set_statement = set_statement[:-2]  # remove trailing ", "
        self._curs.execute(f"UPDATE node_state SET {set_statement} WHERE id=1;")
        if commit:
            self._conn.commit()

    def get_node_state(self) -> Union[dict, None]:
        res = self._curs.execute(f"SELECT * from node_state;")
        results = res.fetchall()
        if not results:
            return
        assert len(results) == 1, "multiple rows in node_state table"
        node_state = results[0]
        return {
            "network": node_state[1],
            "ibd": True if node_state[2] == "TRUE" else False,
            "progress": node_state[3],
            "running": True if node_state[4] == "TRUE" else False,
            "difficulty": node_state[5],
            "height": node_state[6],
            "bestblockheaderhash": node_state[7],
            "time": node_state[8],
            "mediantime": node_state[9],
        }
