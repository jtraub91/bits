"""
P2P and stuff

https://developer.bitcoin.org/devguide/p2p_network.html
https://developer.bitcoin.org/reference/p2p_networking.html
https://en.bitcoin.it/wiki/Network
https://en.bitcoin.it/wiki/Protocol_documentation
"""
import asyncio
import json
import logging
import logging.handlers
import os
import random
import sqlite3
import time
import traceback
from asyncio import Event, StreamReader, StreamWriter, AbstractEventLoop
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from ipaddress import ip_address
from sqlite3 import Cursor
from threading import Thread, Lock
from typing import Any, List, Optional, Tuple, Union

import bits
import bits.blockchain
import bits.constants
import bits.crypto
import bits.ordinals
import bits.script
import bits.tx
from bits.blockchain import Block, Blockheader, Bytes, genesis_block
from bits.tx import Tx

BITS_USER_AGENT = f"/bits:{bits.__version__}/"

MSG_HEADER_LEN = 24

# https://en.bitcoin.it/wiki/Network#Messages
COMMANDS = [
    b"version",
    b"verack",
    b"addr",
    b"inv",
    b"getdata",
    b"getblocks",
    b"getheaders",
    b"tx",
    b"block",
    b"headers",
    b"getaddr",
    b"submitorder",
    b"checkorder",
    b"reply",
    b"alert",
    b"ping",
    b"pong",
]

# services
# https://developer.bitcoin.org/reference/p2p_networking.html#version
UNNAMED = 0x00
NODE_NETWORK = 0x01
NODE_GETUTXO = 0x02
NODE_BLOOM = 0x04
NODE_WITNESS = 0x08
NODE_XTHIN = 0x10
NODE_NETWORK_LIMITED = 0x0400

# https://github.com/bitcoin/bitcoin/blob/v23.0/src/protocol.h#L452-L473
# https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
MSG_WITNESS_FLAG = 1 << 30
# UNDEFINED = 0
MSG_TX = 1
MSG_BLOCK = 2
# MSG_WTX = 5
MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4
MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG
MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG
# MSG_FILTERED_WITNESS_BLOCK = MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG
INVENTORY_TYPE_ID = {
    "MSG_TX": MSG_TX,
    "MSG_BLOCK": MSG_BLOCK,
    "MSG_FILTERED_BLOCK": MSG_FILTERED_BLOCK,
    "MSG_CMPCT_BLOCK": MSG_CMPCT_BLOCK,
    "MSG_WITNESS_TX": MSG_WITNESS_TX,
    "MSG_WITNESS_BLOCK": MSG_WITNESS_BLOCK,
}

log = logging.getLogger(__name__)


class PossibleOrphanError(Exception):
    pass


class PossibleForkError(Exception):
    pass


class ConnectBlockError(Exception):
    pass


class AcceptBlockError(Exception):
    pass


class CheckBlockError(Exception):
    pass


class CheckTxError(Exception):
    pass


class AcceptTxError(Exception):
    pass


class PossibleOrphanTxError(Exception):
    pass


class ShutdownException(Exception):
    pass


def msg_ser(
    start_bytes: bytes,
    command: Union[str, bytes],
    payload: bytes = b"",
) -> bytes:
    """
    Serialized p2p message
    """
    if type(command) is not bytes:
        command = command.encode("ascii")
    if command not in COMMANDS:
        raise ValueError("invalid command")
    if len(payload) > bits.constants.MAX_SIZE:
        raise ValueError("payload exceeds MAX_SIZE")
    while len(command) < 12:
        command += b"\x00"
    payload_size = len(payload).to_bytes(4, "little")
    checksum = bits.crypto.hash256(payload)[:4]
    return start_bytes + command + payload_size + checksum + payload


def parse_version_payload(versionpayload_: bytes) -> dict:
    parsed_payload = {
        "protocol_version": int.from_bytes(versionpayload_[:4], "little"),
        "services": int.from_bytes(versionpayload_[4:12], "little"),
        "timestamp": int.from_bytes(versionpayload_[12:20], "little"),
        "addr_recv_services": int.from_bytes(versionpayload_[20:28], "little"),
        "addr_recv_ip_addr": parse_ip_addr(versionpayload_[28:44]),
        "addr_recv_port": int.from_bytes(versionpayload_[44:46], "big"),
        "addr_trans_services": int.from_bytes(versionpayload_[46:54], "little"),
        "addr_trans_ip_addr": parse_ip_addr(versionpayload_[54:70]),
        "addr_trans_port": int.from_bytes(versionpayload_[70:72], "big"),
        "nonce": int.from_bytes(versionpayload_[72:80], "little"),
    }
    # parse compact size uint varint for user_agent_bytes
    user_agent_len, versionpayload_ = bits.parse_compact_size_uint(versionpayload_[80:])
    parsed_payload["user_agent_bytes"] = user_agent_len
    parsed_payload["user_agent"] = versionpayload_[:user_agent_len].decode("utf8")
    parsed_payload["start_height"] = int.from_bytes(
        versionpayload_[user_agent_len : user_agent_len + 4], "little"
    )
    return parsed_payload


def version_payload(
    start_height: int,
    addr_recv_port: int,
    addr_trans_port: int,
    protocol_version: int = 60001,
    services: int = NODE_NETWORK,
    user_agent: bytes = BITS_USER_AGENT,
) -> bytes:
    """
    https://developer.bitcoin.org/reference/p2p_networking.html#version
    """
    timestamp = int(time.time())
    addr_recv_services = 0x00
    addr_recv_ip_addr = "::ffff:127.0.0.1"
    addr_trans_ip_addr = "::ffff:127.0.0.1"
    nonce = 0
    msg = (
        protocol_version.to_bytes(4, "little")
        + services.to_bytes(8, "little")
        + timestamp.to_bytes(8, "little")
        + addr_recv_services.to_bytes(8, "little")
        + addr_recv_ip_addr.encode("ascii")
        + addr_recv_port.to_bytes(2, "big")
        + services.to_bytes(8, "little")  # addr_trans_services
        + addr_trans_ip_addr.encode("ascii")
        + addr_trans_port.to_bytes(2, "big")
        + nonce.to_bytes(8, "little")
        + bits.compact_size_uint(len(user_agent))  # user_agent_bytes
        + user_agent.encode("utf8")
        + start_height.to_bytes(4, "little")
    )
    return msg


def ping_payload(nonce: int) -> bytes:
    # pong payload same as ping
    return nonce.to_bytes(8, "little")


def parse_ping_payload(payload: bytes) -> dict:
    return {"nonce": int.from_bytes(payload, "little")}


def parse_reject_payload(payload: bytes) -> dict:
    message_size, payload = bits.parse_compact_size_uint(payload)
    message = payload[:message_size].decode("ascii")
    payload = payload[message_size:]
    code = payload[:1]
    payload = payload[1:]
    reason_size, payload = bits.parse_compact_size_uint(payload)
    reason = payload[:reason_size].decode("ascii")
    extra_data = payload[reason_size:].decode("ascii")
    return {
        "message": message,
        "code": code,
        "reason": reason,
        "extra_data": extra_data,
    }


def getblocks_payload(
    block_header_hashes: List[bytes],
    stop_hash: bytes = b"\x00" * 32,
    protocol_version: int = 60001,
) -> bytes:
    """
    https://developer.bitcoin.org/reference/p2p_networking.html#getblocks
    """
    return (
        protocol_version.to_bytes(4, "little")
        + bits.compact_size_uint(len(block_header_hashes))
        + b"".join(block_header_hashes)
        + stop_hash
    )


def headers_payload(count: int, headers: List[bytes]) -> bytes:
    """
    Serialized headers message payload
    Args:
        count: int, number of block headers - max of 2000
        headers: List[bytes], block headers
    """
    payload_ = bits.compact_size_uint(count) + b"".join(
        [header + b"\x00" for header in headers]
    )
    return payload_


def getheaders_payload(
    protocol_version: int,
    hash_count: int,
    block_header_hashes: List[bytes],
    stop_hash: bytes,
) -> bytes:
    return (
        protocol_version.to_bytes(4, "little")
        + bits.compact_size_uint(hash_count)
        + b"".join(block_header_hashes)
        + stop_hash
    )


def parse_headers_payload(payload: bytes) -> List[bytes]:
    count, payload = bits.parse_compact_size_uint(payload)
    blockheaderhashes = []
    while payload:
        blockheaderhash = payload[:80]
        transaction_count = payload[80]
        assert transaction_count == 0, "non-zero transaction count"
        payload = payload[81:]
        blockheaderhashes.append(blockheaderhash)
    assert len(blockheaderhashes) == count, "count mismatch"
    return blockheaderhashes


def parse_getheaders_payload(payload: bytes) -> dict:
    parsed_payload = {
        "protocol_version": int.from_bytes(payload[:4], "little"),
    }
    hash_count_byte = payload[4]
    if hash_count_byte < 253:
        hash_count = hash_count_byte
        parsed_payload["hash_count"] = hash_count
        index = 5  # to resume parsing payload below
    elif hash_count_byte == 253:
        hash_count = int.from_bytes(payload[5:7], "little")
        parsed_payload["hash_count"] = hash_count
        index = 7
    elif hash_count_byte == 254:
        hash_count = int.from_bytes(payload[7:11], "little")
        parsed_payload["hash_count"] = hash_count
        index = 11
    elif hash_count_byte == 255:
        hash_count = int.from_bytes(payload[11:19], "little")
        parsed_payload["hash_count"] = hash_count
        index = 19

    if hash_count > 0:
        # pylint: disable-next=possibly-used-before-assignment
        block_header_hashes = payload[index : index + hash_count * 32]
        parsed_payload["block_header_hashes"] = [
            block_header_hashes[32 * i : 32 * (i + 1)].hex()
            for i in range(1, 1 + len(block_header_hashes) // 32)
        ]
        parsed_payload["stop_hash"] = payload[
            index + hash_count * 32 : index + hash_count * 32 + 32
        ].hex()
        if payload[index + hash_count * 32 + 32 :]:
            raise ValueError(f"parse error, data longer than expected: {len(payload)}")
    else:
        parsed_payload["stop_hash"] = payload[index : index + 32].hex()
        if payload[index + 32 :]:
            raise ValueError(f"parse error, data longer than expected: {len(payload)}")
    return parsed_payload


def parse_feefilter_payload(payload: bytes) -> dict:
    assert len(payload) == 8
    return {"feerate": int.from_bytes(payload, "little")}


def parse_sendcmpct_payload(payload: bytes) -> dict:
    assert len(payload) == 9
    return {"announce": payload[0], "version": int.from_bytes(payload[1:], "little")}


def parse_inv_payload(payload: bytes) -> dict:
    # count encoded as compact_size_uint
    count, payload = bits.parse_compact_size_uint(payload)
    ret = {"count": count, "inventory": []}
    INVENTORY_LEN = 36
    for i in range(count):
        parsed_inventory = parse_inventory(
            payload[i * INVENTORY_LEN : (i + 1) * INVENTORY_LEN]
        )
        ret["inventory"].append(parsed_inventory)
    return ret


parse_notfound_payload = parse_inv_payload


def inventory(type_id: str, hash: str) -> bytes:
    """
    inventory data structure
    https://developer.bitcoin.org/glossary.html#term-Inventory
    Args:
        type_id: str, type of inventory item
        hash: str, hash of inventory item (big endian)
    """
    return (
        int.to_bytes(INVENTORY_TYPE_ID[type_id.upper()], 4, "little")
        + bytes.fromhex(hash)[::-1]
    )


def inv_payload(count: int, inventories: List[inventory]) -> bytes:
    """
    Create inv message payload
    Args:
        count: int, number of inventories
        inventories: List[inventory], list of inventory data structures
    """
    return bits.compact_size_uint(count) + b"".join(inventories)


def parse_inventory(inventory_: bytes) -> dict[str, str]:
    """
    Parse inventory data structure
    Returns:
        {
            "type_id": str, type of inventory item,
            "hash": str, hash of inventory item (big endian)
        }
    """
    assert len(inventory_) == 36
    type_id_integer = int.from_bytes(inventory_[:4], "little")
    type_id = list(
        filter(lambda item: item[1] == type_id_integer, INVENTORY_TYPE_ID.items())
    )[0][0]
    return {"type_id": type_id, "hash": inventory_[4:][::-1].hex()}


def network_ip_addr(time: int, services: bytes, ip_addr: bytes, port: int) -> bytes:
    """
    Network ip address format
    # https://developer.bitcoin.org/reference/p2p_networking.html#addr
    """
    return time.to_bytes(4, "little") + services + ip_addr + port.to_bytes(2, "big")


def parse_network_ip_addr(payload: bytes) -> dict:
    return {
        "time": int.from_bytes(payload[:4], "little"),
        "services": int.from_bytes(payload[4:12], "little"),
        "host": parse_ip_addr(payload[12:28]),
        "port": int.from_bytes(payload[28:], "big"),
    }


def parse_ip_addr(ip_addr: bytes) -> str:
    ip = ip_address(ip_addr)
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip.exploded)


def addr_payload(count: int, addrs: List[bytes]) -> bytes:
    """
    Args:
        count: int, number of ip address (max 1,000)
        addrs: List[bytes], ip addresses in network ip addr format
    """
    return bits.compact_size_uint(count) + b"".join(addrs)


def parse_addr_payload(payload: bytes) -> dict:
    count, payload = bits.parse_compact_size_uint(payload)
    # network ip addrs have 30-byte fixed length
    network_ip_addrs = [
        parse_network_ip_addr(payload[30 * i : 30 * (i + 1)]) for i in range(count)
    ]
    return {"addrs": network_ip_addrs}


def parse_payload(command, payload) -> Union[bytes, dict]:
    parse_fn_name = f"parse_{command.decode('ascii')}_payload"
    parse_fn = globals().get(parse_fn_name)
    if parse_fn:
        return parse_fn(payload)
    else:
        log.warning(f"no parser {parse_fn_name}")
        return payload


def make_request(
    node_requests_path: str,
    method: str,
    args: Tuple = (),
    kwargs: dict = {},
    timeout: int = 10,
    archive_request: bool = False,
) -> Any:
    """
    Make request to running P2P Node and wait for response

    Uses file based IPC approach, i.e.
    writes request to a json file in Node._requests_dir,
    and waits for a response json in the same directory.

    request / response json files are cleaned up by the running Node, and this function, respectively,
    upon request servicing, and response receipt, respectively (or on error).

    # TODO: allow option for archiving past requests

    Args:
        node_requests_path: str, path to Node requests directory
        method: str, method to call on Node
        args: Tuple, method args
        kwargs: dict, method kwargs
        timeout: int, request timeout
        archive_request: bool, True to archive request/response after completion
    """
    timestamp = int(time.time() * 1000)
    request = {
        "method": method,
        "args": args,
        "kwargs": kwargs,
    }
    request_filename = f"{timestamp}_request.json"
    request_filepath = os.path.join(node_requests_path, request_filename)
    log.trace(f"writing {request_filename} ...")
    with open(request_filepath, "w") as f:
        json.dump(request, f)
    response_filename = f"{timestamp}_response.json"
    response_filepath = os.path.join(node_requests_path, response_filename)
    time_start = time.time()
    while not os.path.exists(response_filepath):
        if time.time() - time_start > timeout:
            try:
                os.remove(request_filepath)
                log.debug(f"removed {request_filename}.")
            except FileNotFoundError:
                pass
            raise TimeoutError("timeout waiting for response from Node")
        time.sleep(0.5)
    log.trace(f"reading {response_filename} ...")
    with open(response_filepath, "r") as f:
        response = json.load(f)
    os.remove(response_filepath)
    log.trace(f"removed {response_filename}.")
    return response["return"]


class Peer:
    def __init__(self, host: Union[str, bytes], port: int, network: str, datadir: str):
        self.host = host
        self.port = port
        self.datadir = datadir

        if network.lower() == "mainnet":
            self.magic_start_bytes = bits.constants.MAINNET_START
        elif network.lower() == "testnet":
            self.magic_start_bytes = bits.constants.TESTNET_START
        elif network.lower() == "regtest":
            self.magic_start_bytes = bits.constants.REGTEST_START
        else:
            raise ValueError(f"network not recognized: {network}")

        self._last_recv_msg_time: float = None
        self._last_recv_pong_time: float = None

        self.reader: StreamReader = None
        self.writer: StreamWriter = None

        self.addrs = []
        self.inventories = []
        self._header_processing_queue = deque([])
        self._orphan_blocks = {}
        self._pending_getdata_requests = deque([])
        self._pending_getblocks_request = None
        self._pending_getheaders_request = None
        self._pending_ping_requests: List[dict] = []  # [{nonce, time}]

        self.type: str = "outgoing"  # incoming or outgoing

        self.exit_event = Event()

    def __repr__(self):
        return f"peer(host='{self.host}', port={self.port})"

    async def connect(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        self.reader = reader
        self.writer = writer

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
        log.info(f"closed socket connection to {self}")

    async def recv_msg(self) -> Tuple[bytes, bytes, bytes]:
        """
        Read and deserialize message ( header + payload )
        """
        msg = b""
        while len(msg) != MSG_HEADER_LEN:
            if self.exit_event.is_set():
                raise ShutdownException(
                    f"exit event detected during header read loop {self}"
                )
            msg += await self.reader.read(MSG_HEADER_LEN - len(msg))
            await asyncio.sleep(0)

        start_bytes = msg[:4]
        command = msg[4:16].rstrip(b"\x00")
        payload_size = int.from_bytes(msg[16:20], "little")
        checksum = msg[20:24]

        payload = b""
        if payload_size:
            while len(payload) != payload_size:
                if self.exit_event.is_set():
                    raise ShutdownException(
                        f"exit event detected during payload read loop {self}"
                    )
                payload += await self.reader.read(payload_size - len(payload))
                await asyncio.sleep(0)

        if checksum != bits.crypto.hash256(payload)[:4]:
            raise ValueError(
                f"checksum failed. {checksum} != {bits.crypto.hash256(payload)[:4]}"
            )
        if start_bytes != self.magic_start_bytes:
            raise ValueError(
                f"magic network bytes mismatch - {start_bytes} not equal to magic start bytes {self.magic_start_bytes}"
            )
        log.info(
            f"read {len(start_bytes + command + payload)} bytes from {self}. command: {command}"
        )
        self._last_recv_msg_time = time.time()

        return start_bytes, command, payload

    async def send_command(self, command: bytes, payload: bytes = b""):
        try:
            message_bytes = msg_ser(self.magic_start_bytes, command, payload)
            self.writer.write(message_bytes)
            await self.writer.drain()
            log.info(f"sent {command} and {len(payload)} payload bytes to {self}.")
            log.trace(f"payload: {payload}")
        except ConnectionResetError as err:
            log.error(err)
            log.info(f"connection reset while sending {command} to {self}.")
            self.exit_event.set()
            log.info(f"{self} exit event set")


class Node:
    def __init__(
        self,
        seeds: List[Tuple[str, int]],
        datadir: str,
        network: str,
        log_level: str = "debug",
        protocol_version: int = 60001,
        services: int = NODE_NETWORK,
        user_agent: bytes = BITS_USER_AGENT,
        max_incoming_peers: int = 3,
        max_outgoing_peers: int = 3,
        index_ordinals: bool = False,
        miner_wallet_address: str = "",
        bind: Optional[Tuple[str, int]] = None,
    ):
        """
        bits P2P node

        Args:
            seeds: list[Tuple[str, int]], list of seed nodes to connect to, (host, port) e.g. [("127.0.0.1", 18443),]
            datadir: str, data directory, block data will be stored in <datadir>/blocks
            network: str, network, e.g. "mainnet", "testnet", or "regtest", sets magic start bytes
            protocol_version: int
            services: int
            user_agent: bytes
        """
        if bind:
            self._bind = bind
        elif network == "mainnet":
            self._bind = ("0.0.0.0", 10101)
        elif network == "testnet":
            self._bind = ("0.0.0.0", 20202)
        elif network == "regtest":
            self._bind = ("0.0.0.0", 30303)
        else:
            raise ValueError(f"unknown network: {network}")

        self._connect_seeds_task = None
        self._connect_seeds_exit_event = Event()

        self._miner_wallet_address = miner_wallet_address
        self._index_ordinals = index_ordinals
        self.max_incoming_peers = max_incoming_peers
        self.max_outgoing_peers = max_outgoing_peers

        datadir = os.path.expanduser(datadir)
        if not os.path.exists(datadir):
            os.makedirs(datadir)
        self.datadir = datadir
        blocksdir = os.path.join(self.datadir, "blocks")
        if not os.path.exists(blocksdir):
            os.mkdir(blocksdir)
        self.blocksdir = blocksdir
        self._requests_dir = os.path.join(self.datadir, "_requests")
        if not os.path.exists(self._requests_dir):
            os.mkdir(self._requests_dir)
        self.protocol_version = protocol_version
        self.services = services
        self.user_agent = user_agent
        if network.lower() == "mainnet":
            self.magic_start_bytes = bits.constants.MAINNET_START
        elif network.lower() == "testnet":
            self.magic_start_bytes = bits.constants.TESTNET_START
        elif network.lower() == "regtest":
            self.magic_start_bytes = bits.constants.REGTEST_START
        else:
            raise ValueError(f"network not recognized: {network}")
        self.network = network
        self.log_level = log_level
        fh = logging.handlers.RotatingFileHandler(
            os.path.join(self.datadir, "p2p.log"),
            maxBytes=32 * 1024 * 1024,  # 32MB
            backupCount=3,
        )
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"
        )
        fh.setFormatter(formatter)
        fh.setLevel(getattr(logging, self.log_level.upper()))
        log.addHandler(fh)

        # check for local block dat file
        blocksdir_files = os.listdir(self.blocksdir)
        block_dat_files = [f for f in blocksdir_files if f.endswith(".dat")]
        assert (
            blocksdir_files == block_dat_files
        ), f"non .dat files found in {self.blocksdir}"

        self.index_db_filename = "index.db"
        self.index_db_filepath = os.path.join(self.datadir, self.index_db_filename)
        self.db = Db(self.index_db_filepath)
        self.db.create_tables()
        self._thread_lock = Lock()  # use for db writes

        self.peer_db_filename = "peers.db"
        self.peer_db_filepath = os.path.join(self.datadir, self.peer_db_filename)
        self.peer_db = PeerDb(self.peer_db_filepath)
        self.peer_db.create_tables()
        self._peer_db_lock = Lock()

        if not block_dat_files:
            # if there are no dat files yet,

            # write genesis block to disk
            gb = Block(genesis_block(network=self.network))
            self.save_block(
                gb, bits.blockchain.new_chainwork((b"\x00" * 32).hex(), gb["nBits"])
            )

            # update utxoset
            genesis_coinbase_tx = gb["txns"][0]
            with self._thread_lock:
                self.db.add_tx(genesis_coinbase_tx["txid"], gb["blockheaderhash"], 0)
                self.db.add_to_utxoset(
                    genesis_coinbase_tx["txid"],
                    0,
                    gb["blockheaderhash"],
                    [(0, bits.block_reward(0) - 1)],
                    index_ordinals=self._index_ordinals,
                )

        self.message_queue = asyncio.Queue()

        self._block_processing_queue = asyncio.Queue(maxsize=128)
        self._block_cache: dict[str, dict] = {}
        # block cache e.g.
        # {"<blockheaderhash": {"time": <time:int>, "data": <block:Block>}, ...}
        # upon each entry, record time stamp,
        # and remove oldest entry if greater than MAX_BLOCK_CACHE_SIZE

        self._mempool = []
        self._mempool_tx_processing_queue = deque([])

        self.incoming_peers: List[Peer] = []
        self.outgoing_peers: List[Peer] = []

        self.seeds = [Peer(seed[0], seed[1], network, datadir) for seed in seeds]
        cursor = self.peer_db._conn.cursor()
        cursor.execute(
            "SELECT host, port FROM peer WHERE type='outgoing' ORDER BY time DESC;"
        )
        peer_query = cursor.fetchall()
        cursor.close()
        self.former_peers: List[Peer] = [
            Peer(peer[0], peer[1], self.network, self.datadir) for peer in peer_query
        ]

        self.peers: List[Peer] = []

        self.exit_event = Event()
        self.peer_inactivity_timeout = 5400  # 90 minutes

        self._thread_pool_executor = ThreadPoolExecutor(max_workers=5)

    def get_mempool_txns(self):
        return [tx_.hex() for tx_ in self._mempool]

    ### handlers ###
    def handle_feefilter_command(self, peer: Peer, command: bytes, payload: bytes):
        payload = parse_feefilter_payload(payload)
        with self._thread_lock:
            cursor = self.peer_db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET feefilter_feerate={payload['feerate']} WHERE host='{peer.host}' AND port={peer.port};"
            )
            self.peer_db._conn.commit()
            cursor.close()

    def handle_sendheaders_command(self, peer: Peer, command: bytes, payload: bytes):
        with self._thread_lock:
            cursor = self.peer_db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET sendheaders=1 WHERE host='{peer.host}' AND port={peer.port};"
            )
            self.peer_db._conn.commit()
            cursor.close()

    def handle_reject_command(self, peer: Peer, command: bytes, payload: bytes):
        """
        https://developer.bitcoin.org/reference/p2p_networking.html#reject
        """
        reject = parse_reject_payload(payload)
        log.debug(reject)

    async def handle_addr_command(self, peer: Peer, command: bytes, payload: bytes):
        addrs = parse_addr_payload(payload)["addrs"]
        log.info(f"{len(addrs)} network addrs received from {peer}")
        addrs_added = 0
        for addr in addrs:
            if addr not in peer.addrs:
                peer.addrs.append(addr)
                addrs_added += 1
        log.info(
            f"{addrs_added} new addrs added stored in memory for {peer}. total peer addrs: {len(peer.addrs)}"
        )

    def handle_getaddr_command(self, peer: Peer, command: bytes, payload: bytes):
        log.warning(
            f"no action taken for {command} command from {peer} with {len(payload)} payload bytes"
        )

    def handle_inv_command(self, peer: Peer, command: bytes, payload: bytes):
        parsed_payload = parse_inv_payload(payload)
        count = parsed_payload["count"]
        inventories = parsed_payload["inventory"]

        inventories = [inv for inv in inventories if inv["type_id"] == "MSG_BLOCK"]

        peer_inventories = peer.inventories

        new_inventories = [inv for inv in inventories if inv not in peer_inventories]
        peer.inventories.extend(new_inventories)
        log.info(
            f"{len(new_inventories)} new inventories added for {peer}, total: {len(peer.inventories)}"
        )

    def handle_headers_command(self, peer: Peer, command: bytes, payload: bytes):
        blockheaders = parse_headers_payload(payload)
        blockheaders = [
            Blockheader(blockheader) for blockheader in blockheaders
        ]  # say that 10 times fast
        if blockheaders:
            first_blockheader = blockheaders[0]
            if (
                first_blockheader["prev_blockheaderhash"]
                == peer._pending_getheaders_request
            ):
                peer._pending_getheaders_request = None

        peer._header_processing_queue.extend(blockheaders)
        log.debug(
            f"{len(peer._header_processing_queue)} blockheaders in queue for {peer}"
        )

    def handle_tx_command(self, peer: Peer, command: bytes, payload: bytes):
        tx_ = Tx(payload)
        self._mempool_tx_processing_queue.append(tx_)
        log.debug(
            f"added {tx_['txid']} to mempool processing queue. total txns in queue: {len(self._mempool_tx_processing_queue)}"
        )

        pending_getdata_request_match = next(
            filter(
                lambda inv: inv["type_id"] == "MSG_TX" and inv["hash"] == tx_["txid"],
                peer._pending_getdata_requests,
            ),
            None,
        )
        if pending_getdata_request_match:
            peer._pending_getdata_requests.remove(pending_getdata_request_match)
            pending_getdata_request_match.pop("time")
            pending_getdata_request_match.pop("retries")
            peer.inventories.remove(pending_getdata_request_match)

    async def handle_block_command(self, peer: Peer, command: bytes, payload: bytes):
        block = Block(payload)

        await self._block_processing_queue.put(block)
        log.debug(
            f"block {block['blockheaderhash']} from {peer} added to processing queue. total blocks in queue: {self._block_processing_queue.qsize()}"
        )

        pending_getdata_request_match = next(
            filter(
                lambda inv: inv["type_id"] == "MSG_BLOCK"
                and inv["hash"] == block["blockheaderhash"],
                peer._pending_getdata_requests,
            ),
            None,
        )

        if pending_getdata_request_match:
            peer._pending_getdata_requests.remove(pending_getdata_request_match)
            pending_getdata_request_match.pop("time")
            pending_getdata_request_match.pop("retries")
            peer.inventories.remove(pending_getdata_request_match)
        if (
            peer._pending_getblocks_request
            and peer._pending_getblocks_request["blockheaderhash"]
            == block["prev_blockheaderhash"]
        ):
            peer._pending_getblocks_request = None

    def handle_sendcmpct_command(self, peer: Peer, command: bytes, payload: bytes):
        payload = parse_sendcmpct_payload(payload)
        with self._thread_lock:
            cursor = self.peer_db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET sendcmpct_announce={payload['announce']}, sendcmpct_version={payload['version']} WHERE host='{peer.host}' AND port={peer.port};"
            )
            self.peer_db._conn.commit()
            cursor.close()

    async def handle_getheaders_command(
        self, peer: Peer, command: bytes, payload: bytes
    ):
        payload = parse_getheaders_payload(payload)
        log.warning(f"no action taken for {command} command with payload {payload}")
        # await peer.send_command(b"headers")

    def handle_pong_command(self, peer: Peer, command: bytes, payload: bytes):
        ping_payload = parse_ping_payload(payload)
        pending_ping_req = [
            req
            for req in peer._pending_ping_requests
            if req["nonce"] == ping_payload["nonce"]
        ]
        if pending_ping_req:
            pending_ping_req = pending_ping_req[0]
            peer._pending_ping_requests.remove(pending_ping_req)
            peer._last_recv_pong_time = time.time()
            log.info(
                f"{peer} responded to ping in {time.time() - pending_ping_req['time']} seconds"
            )
        else:
            log.warning(f"{peer} sent pong without matching ping request")

    async def handle_ping_command(self, peer: Peer, command: bytes, payload: bytes):
        """
        Handle ping command by sending a 'pong' message
        """
        payload = parse_ping_payload(payload)
        await peer.send_command(b"pong", ping_payload(payload["nonce"]))

    async def connect_to_peer(self, peer: Peer, timeout: int = 3) -> dict:
        """
        Connect to peer by performing version / verack handshake
        https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
        Args:
            peer: Peer, peer to connect to
            timeout: int, connection timeout
        Returns:
            version_data: dict, parsed version payload from peer
        """
        peer.exit_event.clear()
        # check for max outgoing peers
        if len(self.outgoing_peers) >= self.max_outgoing_peers:
            log.warning(f"max_outgoing_peers reached, connect_peers loop exit.")
            return False

        # attempt to connect to peer socket
        log.trace(f"connecting to {peer}...")
        try:
            await asyncio.wait_for(peer.connect(), timeout)
        except Exception as err:
            log.error(f"error attempting to connect to {peer} - {err}")
            return False
        log.info(f"connected to {peer}")

        # retrieve or create peer in db
        peer_data = self.peer_db.get_peer(peer.host, peer.port)
        if not peer_data:
            with self._peer_db_lock:
                self.peer_db.save_peer(peer.host, peer.port)
            log.info(f"{peer} saved to {self.peer_db_filename}.")

        # attempt to complete connection to outgoing peer by performing version / verack handshake

        # send version message
        trans_sock = peer.writer.transport.get_extra_info("socket")
        local_host, local_port = (
            trans_sock.getsockname()[0],
            trans_sock.getsockname()[1],
        )
        versionp = version_payload(
            self.db.get_blockchain_height(),
            peer.port,
            local_port,
            protocol_version=self.protocol_version,
            services=self.services,
            user_agent=self.user_agent,
        )
        await peer.send_command(b"version", versionp)

        # wait for version message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"version", f"expected version command not {command}"

        # save version payload peer data
        version_data = parse_payload(command, payload)
        log.debug(f"{peer} version payload: {version_data}")

        # send verack
        await peer.send_command(b"verack")

        # wait for verack message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"verack", f"expected verack command, not {command}"

        log.info(f"connection handshake established for {peer}")

        # update peer db with version data
        peer._version_data = version_data
        with self._peer_db_lock:
            cursor = self.peer_db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET protocol_version={version_data['protocol_version']}, services={version_data['services']}, user_agent='{version_data['user_agent']}', start_height='{version_data['start_height']}', time={int(time.time())}, type='outgoing' WHERE host='{peer.host}' AND port={peer.port};"
            )
            cursor.close()
            self.peer_db._conn.commit()
        log.info(f"version data for {peer} saved to {self.peer_db_filename}")
        self.outgoing_peers.append(peer)
        asyncio.create_task(self.peer_recv_loop(peer))
        asyncio.create_task(peer.send_command(b"getaddr"))

        return version_data

    async def connect_from_peer(self, peer: Peer):
        """
        Connect from incoming peer

        Unlike connect_to_peer, this function is called with the peer socket connection already established.

        Args:
            peer: Peer, peer to connect from by performing version / verack handshake
        """
        # retrieve or create peer in db
        peer_data = self.peer_db.get_peer(peer.host, peer.port)
        if not peer_data:
            with self._peer_db_lock:
                self.peer_db.save_peer(peer.host, peer.port)
            log.info(f"{peer} saved to {self.peer_db_filename}")

        # wait for version message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"version", f"expected version command not {command}"

        # save version payload peer data
        version_data = parse_payload(command, payload)
        log.debug(f"{peer} version payload: {version_data}")

        # send version
        trans_sock = peer.writer.transport.get_extra_info("socket")
        local_host, local_port = trans_sock.getsockname()
        versionp = version_payload(
            self.db.get_blockchain_height(),
            peer.port,
            local_port,
            protocol_version=self.protocol_version,
            services=self.services,
            user_agent=self.user_agent,
        )
        await peer.send_command(b"version", versionp)

        # send verack
        await peer.send_command(b"verack")

        # wait for verack message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"verack", f"expected verack command, not {command}"

        log.info(f"connection handshake established for {peer}")

        # save version data for peer in db
        peer._version_data = version_data
        with self._peer_db_lock:
            cursor = self.peer_db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET protocol_version={version_data['protocol_version']}, services={version_data['services']}, user_agent='{version_data['user_agent']}', start_height='{version_data['start_height']}', time={int(time.time())}, type='incoming' WHERE host='{peer.host}' AND port={peer.port};"
            )
            cursor.close()
            self.peer_db._conn.commit()
        log.info(f"version data for {peer} saved to {self.peer_db_filename}")
        self.incoming_peers.append(peer)
        asyncio.create_task(self.peer_recv_loop(peer))
        asyncio.create_task(peer.send_command(b"getaddr"))
        return version_data

    async def peer_recv_loop(self, peer: Peer, msg_timeout: int = 5):
        """
        Args:
            msg_timeout: int, sec to wait before timing out recv_msg
                and looping until exit_event has been set
        """
        log.trace(f"peer_recv_loop started for {peer.type} {peer}")
        try:
            while not peer.exit_event.is_set():
                try:
                    start_bytes, command, payload = await asyncio.wait_for(
                        peer.recv_msg(), int(msg_timeout)
                    )
                except asyncio.TimeoutError as err:
                    timestamp = time.time()

                    if (
                        timestamp - peer._last_recv_msg_time
                        > self.peer_inactivity_timeout
                    ):
                        log.info(f"peer inactivity timeout reached")
                        break

                    if peer._pending_ping_requests:
                        compare_time_ = peer._pending_ping_requests[-1]["time"]
                    else:
                        compare_time_ = peer._last_recv_msg_time
                    if timestamp - compare_time_ > 120 + random.uniform(-2, 2):
                        nonce = random.getrandbits(64)
                        peer._pending_ping_requests.append(
                            {"nonce": nonce, "time": time.time()}
                        )
                        await peer.send_command(b"ping", ping_payload(nonce))

                    if timestamp - compare_time_ > 1200:
                        log.info(f"{peer} pong timeout reached")
                        peer.exit_event.set()
                        log.info(f"{peer} exit event set")
                        break

                except Exception as err:
                    log.error(f"exception occurred during recv_msg for {peer} - {err}")
                    peer.exit_event.set()
                    log.info(f"{peer} exit event set")
                else:
                    await self.message_queue.put((peer, command, payload))
                await asyncio.sleep(0)
        except Exception as err:
            log.error(f"exception occurred in peer_recv_loop for {peer} - {err}")
            log.error(traceback.format_exc())
            peer.exit_event.set()
            return
        finally:
            log.info(f"closing connection to {peer} ...")
            try:
                await peer.close()
                log.info(f"{peer} socket closed")
            except Exception as err:
                log.error(f"exception occurred closing {peer} socket - {err}")
            finally:
                if peer.type == "outgoing":
                    self.outgoing_peers.remove(peer)
                    log.debug(f"{peer} removed from self.outgoing_peers")
                else:
                    self.incoming_peers.remove(peer)
                    log.debug(f"{peer} removed from self.incoming_peers")
            log.trace(f"{peer} peer_recv_loop exit")

    async def handle_incoming_peer(self, reader: StreamReader, writer: StreamWriter):
        host, port = writer.get_extra_info("peername")
        log.info(f"incoming peer connection from {host}:{port}")
        if len(self.incoming_peers) >= self.max_incoming_peers:
            log.warning(
                f"max incoming peers reached. closing new connection from {host}:{port} ..."
            )
            writer.close()
            return
        peer = Peer(host, port, self.network, self.datadir)
        peer.reader = reader
        peer.writer = writer
        peer.type = "incoming"
        try:
            connect_from_peer_task = asyncio.create_task(self.connect_from_peer(peer))
            await asyncio.wait_for(connect_from_peer_task, 5)
        except Exception as err:
            log.error(
                f"exception while attempting to complete connection handshake for {peer} - {err}"
            )
            log.error(traceback.format_exc())

    async def incoming_peer_server(self, bind_address: str, bind_port: int):
        server = await asyncio.start_server(
            self.handle_incoming_peer, bind_address, bind_port
        )
        log.info(f"incoming peer server started @ {bind_address}:{bind_port}")
        async with server:
            while not self.exit_event.is_set():
                await asyncio.sleep(0)
        log.trace("incoming peer server exit")

    async def main_loop(self):
        """
        This is the main loop task, that controls the control operation of the node,
        i.e. sending ping messages, relaying blocks and txns, etc.
        """
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():

            current_blockheight = self.db.get_blockchain_height()
            current_block_index_data = self.db.get_block(current_blockheight)

            if len(self.outgoing_peers) < self.max_outgoing_peers:
                peers = self.incoming_peers + self.outgoing_peers
                peer_addrs = [(peer.host, peer.port) for peer in peers]
                seed_candidates = [
                    seed
                    for seed in self.seeds
                    if (seed.host, seed.port) not in peer_addrs
                ]
                if seed_candidates:
                    await self.connect_to_peer(seed_candidates[0])
                else:
                    log.debug("no more seed candidates")

                    peer_candidates = [
                        peer
                        for peer in self.former_peers
                        if (peer.host, peer.port) not in peer_addrs
                    ]
                    if peer_candidates:
                        await self.connect_to_peer(peer_candidates[0])
                    else:
                        log.debug("no former peer candidates")

                        addr_candidate = None
                        for peer in peers:
                            for addr in peer.addrs:
                                if (addr["host"], addr["port"]) not in peer_addrs:
                                    addr_candidate = addr
                                    break
                            if addr_candidate:
                                peer.addrs.remove(addr_candidate)
                                break

                        if addr_candidate:
                            peer_candidate = Peer(
                                addr_candidate["host"],
                                addr_candidate["port"],
                                self.network,
                                self.datadir,
                            )
                            await self.connect_to_peer(peer_candidate)
                        else:
                            log.debug("no peer addr candidates")
                            await asyncio.sleep(1)

            if self.outgoing_peers:
                peer = self.outgoing_peers[0]
            elif self.incoming_peers:
                peer = self.incoming_peers[0]
            else:
                log.warning("no peers")
                await asyncio.sleep(1)
                continue

            block_inventories = list(
                filter(lambda inv: inv["type_id"] == "MSG_BLOCK", peer.inventories)
            )
            pending_getdata_requests = list(
                filter(
                    lambda req: req["type_id"] == "MSG_BLOCK",
                    peer._pending_getdata_requests,
                )
            )
            if (
                not block_inventories
                and self._block_processing_queue.qsize() == 0
                and not peer._pending_getblocks_request
            ):
                peer._pending_getblocks_request = {
                    "time": int(time.time()),
                    "blockheaderhash": current_block_index_data["blockheaderhash"],
                }
                await peer.send_command(
                    b"getblocks",
                    getblocks_payload(
                        [
                            bytes.fromhex(current_block_index_data["blockheaderhash"])[
                                ::-1
                            ]
                        ]
                    ),
                )
                log.trace(
                    f"sent getblocks for {current_block_index_data['blockheaderhash']}"
                )
            elif (
                peer._pending_getblocks_request
                and peer._pending_getblocks_request["time"] < time.time() - 15
            ):
                log.debug(
                    f"pending getblocks {peer._pending_getblocks_request} request expired."
                )
                peer._pending_getblocks_request = None
            elif (
                self._block_processing_queue.qsize()
                < self._block_processing_queue.maxsize
                and block_inventories
                and not pending_getdata_requests
            ):
                inventory_list = block_inventories[
                    : self._block_processing_queue.maxsize
                    - self._block_processing_queue.qsize()
                ]

                current_time = int(time.time())
                requests = [
                    {"time": current_time, "retries": 3} | inventory_
                    for inventory_ in inventory_list
                ]
                peer._pending_getdata_requests.extend(requests)
                await peer.send_command(
                    b"getdata",
                    inv_payload(
                        len(inventory_list),
                        [
                            inventory(inv["type_id"], inv["hash"])
                            for inv in inventory_list
                        ],
                    ),
                )
            elif pending_getdata_requests:
                expired_requests = list(
                    filter(
                        lambda req: req["time"] < time.time() - 15,
                        peer._pending_getdata_requests,
                    )
                )
                if expired_requests:
                    for req in expired_requests:
                        req["retries"] -= 1
                        log.debug(
                            f"{peer} pending getdata request timeout - {req}. {req['retries']} attemtps remaining..."
                        )
                        if req["retries"] <= 0:
                            log.debug(f"pending getdata request expired - {req}")
                            peer._pending_getdata_requests.remove(req)
                            req.pop("time")
                            req.pop("retries")
                            peer.inventories.remove(req)
            else:
                log.trace(
                    f"len(block_inventories)={len(block_inventories)}, block_processing_queue.qsize()={self._block_processing_queue.qsize()}, pending_getblocks_request={peer._pending_getblocks_request}, pending_getdata_requests(type=MSG_BLOCK)={pending_getdata_requests}"
                )

            # check for external requests in datdir/requests
            request_files = [
                req
                for req in os.listdir(self._requests_dir)
                if req.endswith("_request.json")
            ]
            if request_files:
                log.debug(
                    f"{len(request_files)} requests found in {self._requests_dir}"
                )
                for request_file in request_files:
                    await loop.run_in_executor(
                        self._thread_pool_executor,
                        self.service_request,
                        request_file,
                        loop,
                    )
            await asyncio.sleep(0.5)
        log.trace("main loop exit")

    def service_request(
        self, request_filename: str, loop_: Optional[AbstractEventLoop] = None
    ):
        """
        Service a request from the requests directory

        Upon receipt of a request, the request is deleted (always),
        and processed if the response does not already exist.

        Note: the requested method must return a json serializable type
        Args:
            request_filename: str, request json filename to be serviced from Node._requests_dir
            loop_: Optional[AbstractEventLoop], event loop to run in for async methods
        """
        log.debug(f"processing {request_filename} ...")
        timestamp = request_filename.split("_")[0]
        with open(os.path.join(self._requests_dir, request_filename), "r") as f:
            request = json.load(f)
        os.remove(os.path.join(self._requests_dir, request_filename))
        log.debug(f"removed {request_filename}.")

        response_filename = f"{timestamp}_response.json"
        response_filepath = os.path.join(self._requests_dir, response_filename)
        if not os.path.exists(response_filepath):
            # process request
            method = request["method"]
            args = request["args"]
            kwargs = request["kwargs"]
            log.debug(f"executing {method} with args: {args}, kwargs: {kwargs} ...")
            fn = getattr(self, method)
            try:
                if asyncio.iscoroutinefunction(fn):
                    future = asyncio.run_coroutine_threadsafe(
                        fn(*args, **kwargs), loop_
                    )
                    ret = future.result()
                else:
                    ret = fn(*args, **kwargs)
            except Exception as err:
                log.error(f"an error occurred while processing request - {err}")
            log.trace(f"writing {response_filename} ...")
            request["return"] = ret
            with open(response_filepath, "w") as f:
                json.dump(request, f)

    async def message_handler_loop(self):
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():
            try:
                peer, command, payload = await asyncio.wait_for(
                    self.message_queue.get(), 1.0
                )
            except asyncio.TimeoutError:
                continue
            if command == b"ping":
                asyncio.create_task(self.handle_ping_command(peer, command, payload))
            elif command == b"getheaders":
                asyncio.create_task(
                    self.handle_getheaders_command(peer, command, payload)
                )
            elif command == b"addr":
                asyncio.create_task(self.handle_addr_command(peer, command, payload))
            elif command == b"block":
                asyncio.create_task(self.handle_block_command(peer, command, payload))
            else:
                handler = getattr(
                    self, f"handle_{command.decode('utf8')}_command", None
                )
                if handler is None:
                    log.warning(f"no handler for {command} command")
                else:
                    await loop.run_in_executor(
                        self._thread_pool_executor, handler, peer, command, payload
                    )
            await asyncio.sleep(0)
        log.trace("message handler loop exited")

    # def accept_mempool_tx(self, tx_: Union[Tx, Bytes, bytes]):
    #     """
    #     Validate and accept transaction to mempool
    #     Args:
    #         tx_: Tx | bytes, transaction data
    #     Throws:
    #         CheckTxError: if tx fails context independent checks
    #         AcceptTxError: if tx fails context dependent checks
    #         PossibleOrphanTxError: if tx is potential orphan
    #     """
    #     if not isinstance(tx_, Tx):
    #         tx_ = Tx(tx_)

    #     if not bits.blockchain.check_tx(tx_):
    #         raise CheckTxError(f"tx {tx_['txid']} failed context independent checks")

    #     # Check tx is not already in mempool
    #     if tx_["txid"] in [tx["txid"] for tx in self._mempool]:
    #         raise AcceptTxError(f"tx {tx_['txid']} already in mempool")

    #     # Check tx is not already in blockchain
    #     if self.db.get_tx(tx_["txid"]):
    #         raise AcceptTxError(f"tx {tx_['txid']} already in blockchain")

    #     # Check inputs exist in UTXO set or mempool
    #     for txin in tx_["txins"]:
    #         prev_tx = None
    #         # Check if input exists in mempool
    #         for mempool_tx in self._mempool:
    #             if mempool_tx["txid"] == txin["prev_txid"]:
    #                 prev_tx = mempool_tx
    #                 break

    #         # If not in mempool, check UTXO set
    #         if not prev_tx:
    #             if not self.db.find_blockheaderhash_for_utxo(txin["prev_txid"]):
    #                 raise PossibleOrphanTxError(
    #                     f"tx {tx_['txid']} input {txin['prev_txid']} not found"
    #                 )

    #     # Check for double spends against mempool
    #     for txin in tx_["txins"]:
    #         for mempool_tx in self._mempool:
    #             for mempool_txin in mempool_tx["txins"]:
    #                 if (
    #                     txin["prev_txid"] == mempool_txin["prev_txid"]
    #                     and txin["prev_tx_output_n"] == mempool_txin["prev_tx_output_n"]
    #                 ):
    #                     raise AcceptTxError(
    #                         f"tx {tx_['txid']} double spends input from tx {mempool_tx['txid']}"
    #                     )

    #     # If all checks pass, add to mempool
    #     self._mempool.append(tx_)
    #     log.info(f"tx {tx_['txid']} accepted to mempool")

    def get_size(self):
        """
        Get size on disk of datadir, including all files and subdirectories

        This includes the blocks, index db, logs, etc.
        """
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(self.datadir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return total_size

    def count_blocks(self):
        """
        Count the number of blocks on disk
        """
        dat_filenames = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        number_of_blocks_on_disk = 0
        for dat_filename in dat_filenames:
            blocks = self.parse_dat_file(os.path.join(self.blocksdir, dat_filename))
            if not blocks:
                continue
            number_of_blocks_on_disk += len(blocks)
        return number_of_blocks_on_disk

    def startup_checks(self):
        """
        Run basic startup checks comparing block data on disk with block data in index db
        """
        blockheight = self.db.get_blockchain_height()
        last_block_index_data = self.db.get_block(blockheight=blockheight)

        dat_files = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        last_dat_filepath = os.path.join(self.blocksdir, dat_files[-1])
        last_dat_file_relpath = os.path.relpath(last_dat_filepath, start=self.datadir)
        if not os.path.getsize(os.path.join(self.datadir, last_dat_file_relpath)):
            raise ValueError(
                f"last dat file found on disk ({last_dat_file_relpath}) is empty"
            )

        if last_dat_file_relpath != last_block_index_data["datafile"]:
            raise ValueError(
                f"last block index entry datafile ({last_block_index_data['datafile']}) does not match last dat file found on disk ({last_dat_file_relpath})"
            )

        with open(
            os.path.join(self.datadir, last_block_index_data["datafile"]), "rb"
        ) as dat_file:
            dat_file.seek(last_block_index_data["datafile_offset"])
            _ = dat_file.read(4)
            length = int.from_bytes(dat_file.read(4), "little")
            _ = dat_file.read(length)
            more_data = dat_file.read()
        if more_data:
            raise ValueError(
                "more data found on disk, after last block as indicated in index db"
            )

        for i in range(min(blockheight + 1, 6)):
            log.trace(
                f"checking block {blockheight - i} data and index consistency ..."
            )
            block_index_data = self.db.get_block(blockheight=blockheight - i)
            block = self.get_block_data(
                os.path.join(self.datadir, block_index_data["datafile"]),
                block_index_data["datafile_offset"],
            )
            if block_index_data["blockheaderhash"] != block["blockheaderhash"]:
                raise ValueError(
                    f"blockheaderhash in index db for block {blockheight - i} ({block_index_data['blockheaderhash']}) does not match calculated blockheaderhash for block data on disk ({block['blockheaderhash']})"
                )

    def run(self):
        asyncio.run(
            self.main(),
            debug=True if self.log_level.lower() in ["trace"] else False,
        )

    def start(self):
        self.exit_event.clear()
        self._thread = Thread(target=self.run)
        self._thread.start()

    def stop(self):
        log.info("stopping node gracefully...")
        for peer in self.incoming_peers + self.outgoing_peers:
            peer.exit_event.set()
            log.info(f"{peer} exit event set")
        self.exit_event.set()
        log.info("node exit event set")

    async def main(self):
        self.startup_checks()

        message_handler_loop_task = asyncio.create_task(self.message_handler_loop())
        process_blocks_task = asyncio.create_task(self.process_blocks())
        # asyncio.create_task(self.mine_blocks())
        main_loop_task = asyncio.create_task(self.main_loop())

        incoming_peer_server_task = asyncio.create_task(
            self.incoming_peer_server(self._bind[0], self._bind[1])
        )

        self._tasks = [
            message_handler_loop_task,
            process_blocks_task,
            main_loop_task,
            incoming_peer_server_task,
        ]

        def handle_task_exception(task):
            try:
                task.result()
            except Exception as err:
                log.error(f"task failed: {err}")
                raise err

        for task in self._tasks:
            task.add_done_callback(handle_task_exception)

        await asyncio.wait(self._tasks)
        log.trace("main exit")

    async def request_tx(self, peer: Peer):
        while not self.exit_event.is_set():
            tx_inventories = list(
                filter(lambda inv: inv["type_id"] == "MSG_TX", peer.inventories)
            )
            pending_getdata_requests = list(
                filter(
                    lambda req: req["type_id"] == "MSG_TX",
                    peer._pending_getdata_requests,
                )
            )
            if tx_inventories and not pending_getdata_requests:
                tx_inventory_ = tx_inventories[0]
                peer._pending_getdata_requests.append(
                    {"time": int(time.time()), "retries": 3, **tx_inventory_}
                )
                await peer.send_command(
                    b"getdata",
                    inv_payload(
                        1,
                        [inventory(tx_inventory_["type_id"], tx_inventory_["hash"])],
                    ),
                )
            elif pending_getdata_requests:
                expired_requests = list(
                    filter(
                        lambda req: req["time"] < time.time() - 60,
                        pending_getdata_requests,
                    )
                )
                if expired_requests:
                    for req in expired_requests:
                        req["retries"] -= 1
                        log.debug(
                            f"{peer} pending getdata request timeout - {req}. {req['retries']} attemtps remaining..."
                        )
                        if req["retries"] <= 0:
                            log.debug(f"pending getdata request expired - {req}")
                            peer._pending_getdata_requests.remove(req)
                            req.pop("time")
                            req.pop("retries")
                            peer.inventories.remove(req)
            else:
                log.trace(
                    f"request_tx loop skip. len(tx_inventories)={len(tx_inventories)}, len(pending_getdata_requests)={len(pending_getdata_requests)}"
                )
            await asyncio.sleep(1)
        log.trace("request_tx loop exit")

    async def process_blocks(self):
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():
            try:
                block = await asyncio.wait_for(
                    self._block_processing_queue.get(), timeout=1
                )
                await loop.run_in_executor(
                    self._thread_pool_executor, self.process_block, block
                )
            except asyncio.TimeoutError:
                pass
            except Exception as err:
                log.error(err)
                log.error(traceback.format_exc())
                self.exit_event.set()
            await asyncio.sleep(0)
        log.trace("exit process_blocks")

    def process_block(self, block: Block):
        log.trace(f"processing block {block['blockheaderhash']} ...")
        try:
            self.accept_block(block)
        except (
            PossibleOrphanError,
            CheckBlockError,
            AcceptBlockError,
            PossibleForkError,
        ) as err:
            log.info(err)
            log.info(
                f"{type(err).__name__} for block {block['blockheaderhash']} . discarding ..."
            )
            return

        try:
            cursor = self.db._conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
        except Exception as err:
            log.error(err)
            _deleted_block = self.delete_block()
            try:
                cursor.close()
            except Exception as err:
                log.error(err)
            return

        try:
            self.connect_block(block, cursor=cursor)
        except (ConnectBlockError, Exception) as err:
            log.error(err)
            # rollback tx / utxoset changes
            try:
                cursor.execute("ROLLBACK;")
            except Exception as err:
                log.error(f"rollback failed: {err}")
            try:
                cursor.close()
            except Exception as err:
                log.error(f"cursor close failed: {err}")
            # delete block on disk and index db
            _deleted_block = self.delete_block()
            return

    def delete_block(self) -> Block:
        """
        Delete block chain tip from disk and index db, save node state

        NOTE: This function does NOT rollback the utxoset

        Returns:
            bytes, deleted block
        """
        blockheight = self.db.get_blockchain_height()
        block_index = self.db.get_block(blockheight=blockheight)
        # delete block in index db
        self.db.delete_block(block_index["blockheaderhash"])
        log.info(f"block {blockheight} deleted from {self.index_db_filename}")
        # delete block data on disk
        with open(
            os.path.join(self.datadir, block_index["datafile"]), "rb"
        ) as dat_file:
            truncated_bytes = dat_file.read(block_index["datafile_offset"])
            magic = dat_file.read(4)
            assert magic == self.magic_start_bytes, "magic mismatch"
            length = int.from_bytes(dat_file.read(4), "little")
            deleted_block_data = dat_file.read(length)
            assert len(deleted_block_data) == length, "length mismatch"
        with open(
            os.path.join(self.datadir, block_index["datafile"]), "wb"
        ) as dat_file:
            dat_file.write(truncated_bytes)
        log.info(f"block {blockheight} deleted from {block_index['datafile']}")
        return Block(deleted_block_data)

    def save_block(self, block: bytes, new_chainwork: str):
        """
        Save block to disk, and index db with new chainwork

        observe max_blockfile_size &
        number files blk00000.dat, blk00001.dat, ...

        Args:
            block: Block | Bytes | bytes
            new_chainwork: str, the new total chainwork upon adding this block (added to block index entry)
        """
        dat_files = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        filename = "blk00000.dat" if not dat_files else dat_files[-1]
        filepath = os.path.join(self.blocksdir, filename)
        rel_path = os.path.relpath(filepath, start=self.datadir)

        if self.db.get_blockchain_height() is None:
            # genesis block
            blockheight = 0
        else:
            blockheight = self.db.get_blockchain_height() + 1
        log.trace(f"saving block {blockheight}...")
        blockheader_data = bits.blockchain.block_header_deser(block[:80])

        block_data = self.magic_start_bytes + len(block).to_bytes(4, "little") + block

        # write block data to .dat file(s) on disk
        dat_file = open(filepath, "ab")
        start_offset = dat_file.tell()
        if len(block_data) + start_offset <= bits.constants.MAX_BLOCKFILE_SIZE:
            dat_file.write(block_data)
        else:
            # write new .dat file
            dat_file.close()
            # increment blkxxxxx.dat number by 1
            new_blk_no = int(filename.split(".dat")[0].split("blk")[-1]) + 1
            filename = f"blk{str(new_blk_no).zfill(5)}.dat"
            filepath = os.path.join(self.blocksdir, filename)
            rel_path = os.path.relpath(filepath, start=self.datadir)
            dat_file = open(filepath, "wb")
            start_offset = 0
            dat_file.write(block_data)
        dat_file.close()
        log.info(f"block {blockheight} saved to {filename}")

        # save hash / header to db index
        with self._thread_lock:
            self.db.save_block(
                blockheight,
                blockheader_data["blockheaderhash"],
                blockheader_data["version"],
                blockheader_data["prev_blockheaderhash"],
                blockheader_data["merkle_root_hash"],
                blockheader_data["nTime"],
                blockheader_data["nBits"],
                blockheader_data["nNonce"],
                new_chainwork,
                rel_path,
                start_offset,
            )
        log.info(f"block {blockheight} saved to {self.index_db_filename}")

    def get_blockchain_info(self) -> Union[dict, None]:
        blockheight = self.db.get_blockchain_height()
        block_index_data = self.db.get_block(blockheight)
        cursor = self.db._conn.cursor()
        start_height = cursor.execute(
            "SELECT start_height FROM peer ORDER BY start_height DESC LIMIT 1;"
        ).fetchone()
        start_height = start_height[0] if start_height else None
        cursor.close()
        _ = self.get_block_data(
            os.path.join(self.datadir, block_index_data["datafile"]),
            block_index_data["datafile_offset"],
        )

        last_11_block_index_ = [
            self.db.get_block(blockheight - i) for i in range(min(blockheight + 1, 11))
        ]
        last_11_times = [block_index_["nTime"] for block_index_ in last_11_block_index_]
        return {
            "network": self.network,
            "progress": float(format((blockheight + 1) / (start_height + 1), "0.8f"))
            if start_height is not None
            else None,
            "difficulty": bits.blockchain.difficulty(
                bits.blockchain.target_threshold(
                    bytes.fromhex(block_index_data["nBits"])[::-1]
                ),
                network=self.network,
            ),
            "size": self.get_size(),
            "height": blockheight,
            "blockheaderhash": block_index_data["blockheaderhash"],
            "chainwork": block_index_data["chainwork"],
            "time": block_index_data["nTime"],
            "mediantime": bits.blockchain.median_time(last_11_times),
            "timestamp": datetime.fromtimestamp(
                block_index_data["nTime"], tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S %Z"),
        }

    async def submit_block(self, block: str):
        """
        Submit block to network
        Args:
            block: str, hex encoded block
        """
        block = Block(bytes.fromhex(block))
        await self._block_processing_queue.put(block)
        log.debug(
            f"block {block['blockheaderhash']} added to processing queue. total blocks in queue: {self._block_processing_queue.qsize()}"
        )
        for peer in self.peers:
            await peer.send_command(b"block", block)

    async def submit_tx(self, tx_: str):
        tx_ = Tx(bytes.fromhex(tx_))
        return

    async def mine_blocks(self):
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():
            block = await loop.run_in_executor(
                self._thread_pool_executor,
                self.mine_block,
                self._miner_wallet_address.encode("utf8"),
            )
            log.debug(f"found block: {block.hex()}")
        log.trace("mine_blocks exit")

    def mine_block(self, recv_addr: str, version: int = 2):
        """
        Mine a block, with single coinbase txout paying block reward to recv_addr

        Note: recv_addr can be a pubkey, base58check, or segwit address (as accepted by bits.script.scriptpubkey)

        Args:
            recv_addr: str, address to pay coinbase txout to
            version: int, version of block
        Returns:
            bytes, mined block
        """
        # get current block
        current_blockheight = self.db.get_blockchain_height()
        current_block_index_data = self.db.get_block(blockheight=current_blockheight)
        current_block = Block(
            self.get_block_data(
                os.path.join(self.datadir, current_block_index_data["datafile"]),
                current_block_index_data["datafile_offset"],
            )
        )

        next_blockheight = current_blockheight + 1

        # get mempool txns
        mempool_txns = []

        # create coinbase tx
        scriptpubkey_ = bits.script.scriptpubkey(recv_addr.encode("utf8"))
        txins = [
            bits.tx.coinbase_txin(
                b"bits",
                block_height=next_blockheight,
            )
        ]
        txouts = [
            bits.tx.txout(
                bits.block_reward(next_blockheight),
                scriptpubkey_,
            )
        ]
        coinbase_tx = bits.tx.tx(txins, txouts)

        block_txns = [coinbase_tx] + mempool_txns
        block_txids = [bits.crypto.hash256(tx_) for tx_ in block_txns]

        merkle_root_ = bits.blockchain.merkle_root(block_txids)

        target = bits.blockchain.target_threshold(
            bytes.fromhex(current_block_index_data["nBits"])[::-1]
        )

        # # TODO: consolidate this logic with get_next_nbits
        # if next_blockheight % 2016 == 0:
        #     # difficulty adjustment block

        #     # block 0 of difficulty adjustment period
        #     block_0_index_data = self.db.get_block(blockheight=next_blockheight - 2016)

        #     elapsed_time = current_block_index_data["nTime"] - block_0_index_data["nTime"]

        #     if self.network == "testnet" and elapsed_time >= 1200:
        #         next_nbits = "1d00ffff"
        #     elif self.network == "testnet":
        #         cursor = self.db._conn.cursor()
        #         last_non_max_nbits_query = cursor.execute(
        #             f"SELECT nBits FROM block WHERE nBits!='1d00ffff' AND blockheight>={current_blockheight - (current_blockheight % 2016)} AND blockheight<={current_blockheight} ORDER BY blockheight DESC;"
        #         ).fetchone()
        #         cursor.close()
        #         next_nbits = last_non_max_nbits_query[0] if last_non_max_nbits_query else "1d00ffff"
        #     else:
        #         next_nbits = bits.blockchain.compact_nbits(
        #             bits.blockchain.calculate_new_target(elapsed_time, target)
        #         )[::-1].hex()
        # else:
        #     if self.network == "testnet" and elapsed_time >= 1200:
        #         next_nbits = "1d00ffff"
        #     next_nbits = current_block_index_data["nBits"]
        next_nbits = current_block_index_data["nBits"]

        nonce = 0
        new_blockheader = bits.blockchain.block_header(
            version,
            current_block["blockheaderhash"],
            merkle_root_[::-1].hex(),
            int(time.time()),
            next_nbits,
            nonce,
        )
        hash_start = time.time()
        new_blockheaderhash = bits.crypto.hash256(new_blockheader)
        while (
            int.from_bytes(new_blockheaderhash, "little") > target
            and not self.exit_event.is_set()
        ):
            nonce += 1
            new_blockheader = bits.blockchain.block_header(
                version,
                current_block["blockheaderhash"],
                merkle_root_[::-1].hex(),
                int(time.time()),
                next_nbits,
                nonce,
            )
            new_blockheaderhash = bits.crypto.hash256(new_blockheader)
            if nonce % 1000 == 0:
                log.info(
                    f"mining block {next_blockheight} - {format(nonce/(time.time() - hash_start), '0.2f')} hashes/sec"
                )

        new_block = bits.blockchain.block_ser(
            new_blockheader,
            block_txns,
        )

        return new_block.hex()

    def get_node_info(self) -> Union[dict, None]:
        ret = {"peers": {"incoming": [], "outgoing": []}}
        for peer in self.incoming_peers + self.outgoing_peers:
            peer_data = {}
            cursor = self.db._conn.cursor()
            query = cursor.execute(
                f"SELECT host, port, protocol_version, services, user_agent, start_height FROM peer WHERE host='{peer.host}' AND port={peer.port};"
            ).fetchall()
            cursor.close()
            if query:
                query = query[0]
                peer_data.update(
                    {
                        "host": query[0],
                        "port": query[1],
                        "protocol_version": query[2],
                        "services": query[3],
                        "user_agent": query[4],
                        "start_height": query[5],
                    }
                )
            ret["peers"][peer.type].append(peer_data)
        return ret

    def get_block_data(
        self, datafile: str, datafile_offset: int, cache: bool = False
    ) -> Block:
        """
        Retrieve raw block data from .dat files by datafile name and datafile byte offset
        Args:
            datafile: str, filepath for the dat file containing block data
            datafile_offset: int, byte offset for block in datafile
        Returns:
            block: bytes, raw block data on disk
        """
        with open(datafile, "rb") as dat_file:
            dat_file.seek(datafile_offset)
            start_bytes = dat_file.read(4)
            length = int.from_bytes(dat_file.read(4), "little")
            block = dat_file.read(length)
        assert start_bytes == self.magic_start_bytes, "magic mismatch"
        assert len(block) == length, "block length mismatch"
        if cache:
            blockheaderhash = bits.crypto.hash256(block[:80])[::-1].hex()
            self._block_cache[blockheaderhash] = {
                "time": time.time(),
                "block": Block(block),
            }
            log.debug(f"block {blockheaderhash} saved to cache")

            # remove oldest cached blocks if we've reached max
            total_block_cache_size = sum(
                [len(bc["block"]) for bc in self._block_cache.values()]
            )
            log.trace(f"total block cache size: {total_block_cache_size}")
            if total_block_cache_size > bits.constants.MAX_BLOCKFILE_SIZE:
                oldest_cached_blocks = sorted(
                    self._block_cache.keys(),
                    key=lambda bh: self._block_cache[bh]["time"],
                )
                i = 0
                while total_block_cache_size > bits.constants.MAX_BLOCKFILE_SIZE:
                    self._block_cache.pop(oldest_cached_blocks[i])
                    log.debug(f"block {oldest_cached_blocks[i]} removed from cache")
                    i += 1
                    total_block_cache_size = sum(
                        [len(b["block"]) for b in self._block_cache.values()]
                    )

        return Block(block)

    def parse_dat_file(self, filename) -> List[bytes]:
        """
        Read and parse dat file for raw blocks
        Returns:
            List[bytes]: list of blocks
        """
        blocks = []
        with open(filename, "rb") as dat_file:
            while start_bytes := dat_file.read(4):
                assert (
                    start_bytes == self.magic_start_bytes
                ), f"dat file error - {start_bytes} magic start byte does not match expected {self.magic_start_bytes}"
                length = int.from_bytes(dat_file.read(4), "little")
                block = dat_file.read(length)
                assert (
                    len(block) == length
                ), f"dat file error, actual block byte length {len(block)} does not equal encoded length {length}"
                blocks.append(block)
        return blocks

    def accept_block(
        self,
        block: Union[Block, Bytes, bytes],
    ) -> bool:
        """
        Validate block as new tip and save block data and / or index and chainstate
        Args:
            block: Block | bytes, block data
        Returns:
            bool: True if block is accepted
        Throws:
            CheckBlockError: if block fails context indepedent checks
            AcceptBlockError: if block fails context dependent checks
            PossibleOrphanError: if block is potential orphan
            PossibleForkError: if block is part of a potential fork
            ConnectBlockError: if error is thrown during full tx validation,
                i.e. after block is saved to disk
        """
        current_blockheight = self.db.get_blockchain_height()
        current_block_index_data = self.db.get_block(blockheight=current_blockheight)

        proposed_blockheight = current_blockheight + 1
        proposed_block = Block(block)
        if not bits.blockchain.check_block(proposed_block, network=self.network):
            raise CheckBlockError(
                f"proposed block {proposed_block['blockheaderhash']} failed context independent checks"
            )

        # check for duplicate hash in blockchain index
        if self.db.get_block(blockheaderhash=proposed_block["blockheaderhash"]):
            raise AcceptBlockError(
                f"proposed blockhash {proposed_block['blockheaderhash']} already found in block index db"
            )

        # check prev block hash matches current block hash
        if (
            proposed_block["prev_blockheaderhash"]
            != current_block_index_data["blockheaderhash"]
        ):
            parent = self.db.get_block(
                blockheaderhash=proposed_block["prev_blockheaderhash"]
            )
            if parent:
                raise PossibleForkError(
                    f"proposed block {proposed_block['blockheaderhash']} prev blockheader hash does not match current block {current_blockheight}'s header hash, but parent was found in the chain (block {parent['blockheight']})"
                )
            else:
                raise PossibleOrphanError(
                    f"proposed block {proposed_block['blockheaderhash']} prev blockheader hash does not match current block {current_blockheight}'s header hash"
                )

        # check nBits correctly sets difficulty
        if proposed_block["nBits"] not in self.get_next_nbits(proposed_block):
            raise AcceptBlockError(
                f"proposed block nBits {proposed_block['nBits']} is not in {self.get_next_nbits(proposed_block)}"
            )

        # ensure timestamp is strictly greater than the median_time of last 11 blocks
        last_11_block_index_ = (
            [
                self.db.get_block(current_blockheight - i)
                for i in range(min(current_blockheight + 1, 11))
            ]
            if current_blockheight is not None
            else []
        )
        last_11_times = [block["nTime"] for block in last_11_block_index_]
        median_time = bits.blockchain.median_time(last_11_times)
        if median_time is not None and proposed_block["nTime"] <= median_time:
            raise AcceptBlockError(
                f"proposed block nTime {proposed_block['nTime']} is not strictly greater than the median time {median_time}"
            )

        # ensure timestamp is not more than two hours in future
        current_time = time.time()
        if proposed_block["nTime"] > current_time + 7200:
            raise AcceptBlockError(
                f"proposed block nTime {proposed_block['nTime']} is more than two hours in the future {current_time + 7200}"
            )

        # check all transacations are finalized
        for txn in proposed_block["txns"]:
            if not bits.tx.is_final(
                txn, blockheight=proposed_blockheight, blocktime=proposed_block["nTime"]
            ):
                raise AcceptBlockError(
                    f"block {proposed_block['blockheaderhash']} has non-final transaction {txn['txid']}"
                )

        ### save block to disk and index db ###
        self.save_block(
            block,
            bits.blockchain.new_chainwork(
                current_block_index_data["chainwork"], proposed_block["nBits"]
            ),
        )
        return True

    def connect_block(
        self, block: Union[Block, Bytes, bytes], cursor: Optional[Cursor] = None
    ) -> bool:
        # now we update utxoset step-by-step during tx validation,
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self.db._conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")

        current_blockheight = self.db.get_blockchain_height(cursor=cursor)
        current_block_index_data = self.db.get_block(
            blockheight=current_blockheight, cursor=cursor
        )

        cached_current_block_data = self._block_cache.get(
            current_block_index_data["blockheaderhash"]
        )
        if cached_current_block_data:
            current_block = cached_current_block_data["block"]
        else:
            current_block = self.get_block_data(
                datafile=os.path.join(
                    self.datadir, current_block_index_data["datafile"]
                ),
                datafile_offset=current_block_index_data["datafile_offset"],
                cache=True,
            )

        # get total value spent by coinbase transaction
        coinbase_tx = current_block["txns"][0]
        with self._thread_lock:
            utxo_count = cursor.execute(
                "SELECT COUNT(*) FROM utxoset WHERE txid=?;", (coinbase_tx["txid"],)
            ).fetchone()[0]
            if utxo_count > 0:
                log.debug(
                    f"{utxo_count} utxo(s) with txid {coinbase_tx['txid']} already exist in utxoset"
                )
                if current_blockheight in [91842, 91880]:
                    # two historic violations allowed per BIP 30,
                    # https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
                    log.debug(
                        f"allowing historic BIP 30 violation @ block {current_blockheight}"
                    )
                else:
                    log.error(
                        f"txid {coinbase_tx['txid']} matches prior not-fully-spent transaction"
                    )
                    raise ConnectBlockError(
                        f"txid {coinbase_tx['txid']} matches prior not-fully-spent tx"
                    )
            self.db.add_tx(
                coinbase_tx["txid"],
                current_block["blockheaderhash"],
                0,
                cursor=cursor,
            )

        coinbase_tx_txouts = coinbase_tx["txouts"]
        coinbase_tx_txouts_total_value = 0
        for txo in coinbase_tx_txouts:
            coinbase_tx_txouts_total_value += txo["value"]

        # pool of ordinal ranges to be assigned to outputs
        # first range is newly created corresponding to the block reward
        block_ordinal_ranges = deque(
            [
                (
                    bits.ordinals.from_decimal(f"{current_blockheight}.0"),
                    bits.ordinals.from_decimal(f"{current_blockheight}.0")
                    + bits.block_reward(current_blockheight)
                    - 1,
                )
            ]
        )
        # this pool list will be used to accumulate the ordinal ranges from transaction inputs unspent value i.e. fees

        MIN_TX_FEE = 0

        # tally up the surplus value aka miner fees, block fees,
        # ... "tips" seems like an apt name
        miner_tips = 0
        for txn_i, txn in enumerate(current_block["txns"][1:], start=1):
            with self._thread_lock:
                utxo_count = cursor.execute(
                    "SELECT COUNT(*) FROM utxoset WHERE txid=?;", (txn["txid"],)
                ).fetchone()[0]
                if utxo_count > 0:
                    log.debug(
                        f"{utxo_count} utxo(s) with txid {txn['txid']} already exist in utxoset"
                    )
                    if current_blockheight in [91842, 91880]:
                        # two historic violations allowed per BIP 30,
                        # https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
                        log.debug(
                            f"allowing historic BIP 30 violation @ block {current_blockheight}"
                        )
                    else:
                        log.error(
                            f"txid {txn['txid']} matches prior not-fully-spent transaction"
                        )
                        raise ConnectBlockError(
                            f"txid {txn['txid']} matches prior not-fully-spent tx"
                        )
                self.db.add_tx(
                    txn["txid"],
                    current_block["blockheaderhash"],
                    txn_i,
                    cursor=cursor,
                )

            log.debug(
                f"processing tx {txn_i} of {len(current_block['txns'][1:])} non-coinbase txns in new block {current_blockheight}..."
            )
            txn_txid = txn["txid"]

            tx_ordinal_ranges = deque([])

            txn_value_in = 0
            txn_value_out = 0
            for txin_i, tx_in in enumerate(txn["txins"]):
                txin_txid = tx_in["txid"]
                txin_vout = tx_in["vout"]

                # check for double spending by checking that the transaction exists
                # in the current utxo set
                utxo_blockheaderhash = self.db.find_blockheaderhash_for_utxo(
                    txin_txid,
                )
                if not utxo_blockheaderhash:
                    raise ConnectBlockError(
                        f"a matching blockheaderhash for txo {txin_vout} in txid {txin_txid} was not found in the utxoset"
                    )
                res = cursor.execute(
                    f"SELECT * FROM utxoset WHERE txid='{txin_txid}' AND vout={txin_vout};"
                ).fetchone()
                if not res:
                    raise ConnectBlockError(
                        f"utxo(txid='{txin_txid}', vout={txin_vout}) not found in utxoset"
                    )

                # get the utxo transaction in full
                utxo_block_index_data = self.db.get_block(
                    blockheaderhash=utxo_blockheaderhash,
                    cursor=cursor,
                )
                utxo_blockheight = utxo_block_index_data["blockheight"]
                cached_utxo_block_data = self._block_cache.get(utxo_blockheaderhash)
                if cached_utxo_block_data:
                    utxo_block = cached_utxo_block_data["block"]
                else:
                    utxo_block = self.get_block_data(
                        os.path.join(self.datadir, utxo_block_index_data["datafile"]),
                        utxo_block_index_data["datafile_offset"],
                        cache=True,
                    )

                utxo_tx = next(
                    (t for t in utxo_block["txns"] if t["txid"] == txin_txid)
                )
                log.trace(f"utxo(txid={txin_txid}, vout={txin_vout}) retrieved.")

                # if transaction is coinbase transaction, check that it's matured
                if bits.tx.is_coinbase(utxo_tx):
                    if (
                        current_blockheight - utxo_blockheight
                        < bits.constants.COINBASE_MATURITY
                    ):
                        raise ConnectBlockError(
                            f"coinbase transaction output in block(blockheight={utxo_blockheight}) was used but has not yet matured, current block: block(blockheight={current_blockheight})"
                        )

                # get utxo from utxo_tx referenced in tx_in
                utxo = utxo_tx["txouts"][txin_vout]
                utxo_value = utxo["value"]

                # add utxo value to total transction value input
                txn_value_in += utxo_value

                # evaluate tx_in unlocking script for its utxo
                tx_in_scriptsig = tx_in["scriptsig"]
                utxo_scriptpubkey = utxo["scriptpubkey"]
                script_ = bits.script.script(
                    [tx_in_scriptsig, "OP_CODESEPARATOR", utxo_scriptpubkey]
                )
                log.trace(
                    f"evaluating script for tx input {txin_i} of {len(txn['txins'])} txins in txn {txn_i}/{len(current_block['txns'][1:])} of new block {current_blockheight}..."
                )
                if not bits.script.eval_script(
                    script_, bits.tx.tx_ser(utxo_tx), txin_vout
                ):
                    raise ConnectBlockError(
                        f"script evaluation failed for txin {txin_i} in txn {txn_i} in block(blockheaderhash={current_block['blockheaderhash']})"
                    )

                # this tx_in succeeds, update utxoset
                log.trace(
                    f"removing tx input {txin_i} in txn {txn_i} of new block {current_blockheight} from utxoset..."
                )
                with self._thread_lock:
                    tx_ordinal_ranges += self.db.remove_from_utxoset(
                        txin_txid,
                        txin_vout,
                        index_ordinals=self._index_ordinals,
                        cursor=cursor,
                    )
                log.trace(
                    f"tx input {txin_i} in txn {txn_i} of new block {current_blockheight} removed from utxoset."
                )

            # now loop over txouts, add to total txn value out
            for tx_out in txn["txouts"]:
                txn_value_out += tx_out["value"]

            # check that MIN_TX_FEE is met
            txn_surplus_value = txn_value_in - txn_value_out
            if txn_surplus_value < MIN_TX_FEE:
                raise ConnectBlockError(
                    f"block {current_block['blockheaderhash']} txn {txn_i} surplus value {txn_surplus_value} does not meet minimum {MIN_TX_FEE}"
                )

            # add txn surplus to total miner tips
            miner_tips += txn_surplus_value

            # add newly created utxos to utxoset too
            for vout, txout_ in enumerate(txn["txouts"]):
                value = txout_["value"]
                utxo_ordinal_ranges = []
                if self._index_ordinals:
                    while value > 0:
                        start, end = tx_ordinal_ranges.popleft()

                        if end - start + 1 > value:
                            utxo_ordinal_ranges += [(start, start + value - 1)]
                            tx_ordinal_ranges.appendleft((start + value, end))
                            break
                        else:
                            utxo_ordinal_ranges += [(start, end)]
                            value -= end - start + 1

                log.trace(
                    f"adding tx output {vout} in txn {txn_i} of new block {current_blockheight} to utxoset..."
                )
                with self._thread_lock:
                    self.db.add_to_utxoset(
                        txn["txid"],
                        vout,
                        current_block_index_data["blockheaderhash"],
                        utxo_ordinal_ranges,
                        index_ordinals=self._index_ordinals,
                        replace=current_blockheight
                        in [91842, 91880],  # allow historic violations per BIP 30
                        cursor=cursor,
                    )
            block_ordinal_ranges += tx_ordinal_ranges

        max_block_reward = bits.block_reward(current_blockheight) + miner_tips
        if coinbase_tx_txouts_total_value > max_block_reward:
            raise ConnectBlockError(
                f"block {current_block['blockheaderhash']} coinbase tx spends more than the max block reward"
            )

        for vout, txout_ in enumerate(coinbase_tx_txouts):
            value = txout_["value"]
            utxo_ordinal_ranges = []
            if self._index_ordinals:
                while value > 0:
                    start, end = block_ordinal_ranges.popleft()
                    if end - start + 1 > value:
                        utxo_ordinal_ranges += [(start, start + value - 1)]
                        block_ordinal_ranges.appendleft((start + value, end))
                        break
                    else:
                        utxo_ordinal_ranges += [(start, end)]
                        value -= end - start + 1
            with self._thread_lock:
                self.db.add_to_utxoset(
                    coinbase_tx["txid"],
                    vout,
                    current_block_index_data["blockheaderhash"],
                    utxo_ordinal_ranges,
                    index_ordinals=self._index_ordinals,
                    replace=current_blockheight
                    in [91842, 91880],  # allow historic violations per BIP 30
                    cursor=cursor,
                )

        self.db._conn.commit()
        log.debug(
            f"processed all of {len(current_block['txns'])} txns in block {current_blockheight}."
        )
        if ephemeral_cursor:
            cursor.close()
        return True

    def get_best_peer(self) -> Union[Peer, None]:
        cursor = self.db._conn.cursor()
        chainworks = cursor.execute(
            "SELECT MAX(blockheight), chainwork, peer_id FROM blockheader GROUP BY peer_id;"
        ).fetchall()
        cursor.close()
        sorted_chainworks = sorted(chainworks, key=lambda cw: int(cw[1], 16))
        best_peer_id = sorted_chainworks[-1][2]
        # possible for multiple peers to have best if they are synced, but we dpn't care
        return best_peer_id

    def get_next_nbits(
        self,
        next_block: Union[Block, Blockheader, Bytes, bytes],
        peer_id: Optional[int] = None,
    ) -> set:
        """
        Determine the allowed set of valid nbits for the next block or blockheader

        Implements testnet special rules, if applicable

        This function can be used in the context of accept_block, i.e. adding a new block to our local blockchain,
        or in the context of headers_sync where a peer's header chain is used for blockheader queries

        If a blockheader is provided, peer_id is used to determine which peer's header chain
            is queried for the blockheader context,
            otherwise, if a block is provided, the local block index is queried

        Args:
            next_block: Block | Blockheader | bytes, next block or blockheader
                in which to determine set of valid nBits according to context of
                current block (or header) chain
            peer_id: Optional[Peer], peer
                in the case of header sync, we need to know which peer's header chain
                to do database lookup from
        Returns:

            set, valid nbits for next block(/blockheader)
        """
        if len(next_block) == 80:
            next_block = Blockheader(next_block)
            cursor = self.db._conn.cursor()
            current_blockheight = cursor.execute(
                f"SELECT blockheight FROM blockheader WHERE peer_id='{peer_id}' ORDER BY blockheight DESC LIMIT 1;"
            ).fetchone()[0]
            cursor.close()
            # TODO: refactor this with blockheader table removed
            # current_block_index_data = self.db.get_blockheader(
            #     peer_id, blockheight=current_blockheight
            # )
            current_block_index_data = {"data": "TODO"}
        else:
            next_block = Block(next_block)
            current_blockheight = self.db.get_blockchain_height()
            current_block_index_data = self.db.get_block(current_blockheight)

        next_blockheight = current_blockheight + 1

        # testnet special rule
        # if no block mined in last 20 min, difficulty can be set to 1.0
        # https://en.bitcoin.it/wiki/Testnet
        elapsed_time_for_last_block = (
            next_block["nTime"] - current_block_index_data["nTime"]
        )
        if next_blockheight % 2016:
            # not difficulty adjustment block

            if self.network == "testnet":
                if isinstance(next_block, Block):
                    cursor = self.db._conn.cursor()
                    last_non_max_nbits_query = cursor.execute(
                        f"SELECT nBits FROM block WHERE nBits!='1d00ffff' AND blockheight>={current_blockheight - (current_blockheight % 2016)} AND blockheight<={current_blockheight} ORDER BY blockheight DESC;"
                    ).fetchone()
                    cursor.close()
                elif isinstance(next_block, Blockheader):
                    cursor = self.db._conn.cursor()
                    last_non_max_nbits_query = cursor.execute(
                        f"SELECT nBits FROM blockheader WHERE nBits!='1d00ffff' AND blockheight>={current_blockheight - (current_blockheight % 2016)} AND blockheight<={current_blockheight} AND peer_id={peer_id} ORDER BY blockheight DESC;"
                    ).fetchone()
                    cursor.close()
                last_non_max_nbits = (
                    last_non_max_nbits_query[0]
                    if last_non_max_nbits_query
                    else "1d00ffff"
                )

                next_nbits = [current_block_index_data["nBits"], last_non_max_nbits]

                # testnet special rule allows minimum difficulty
                # when elapsed_time_for_last_block >= 1200
                if elapsed_time_for_last_block >= 1200:
                    next_nbits.append("1d00ffff")

                return set(next_nbits)
            else:
                return set([current_block_index_data["nBits"]])
        else:
            # difficulty adjustment block
            current_target = bits.blockchain.target_threshold(
                bytes.fromhex(current_block_index_data["nBits"])[::-1]
            )

            if isinstance(next_block, Block):
                block_0_index_data = self.db.get_block(
                    current_blockheight - 2015
                )  # first block of difficulty period
            elif isinstance(next_block, Blockheader):
                # TODO: refactor this with blockheader table removed
                # block_0_index_data = self.db.get_blockheader(
                #     peer_id, current_blockheight - 2015
                # )
                block_0_index_data = {"data": "TODO"}

            elapsed_time = (
                current_block_index_data["nTime"] - block_0_index_data["nTime"]
            )

            new_target = bits.blockchain.calculate_new_target(
                elapsed_time, current_target
            )
            new_target_nbits = bits.blockchain.compact_nbits(new_target)[::-1].hex()

            if self.network == "testnet" and elapsed_time_for_last_block >= 1200:
                return set([new_target_nbits, "1d00ffff"])
            else:
                return set([new_target_nbits])


class Db:
    def __init__(self, db_filepath: str):
        self._conn = sqlite3.connect(db_filepath, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.execute("PRAGMA busy_timeout=1000;")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._conn.close()

    def create_tables(self):
        self.create_block_table()
        self.create_tx_table()
        self.create_utxoset_table()
        self.create_ordinal_range_table()

    def create_block_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='block';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE block(
                    id INTEGER PRIMARY KEY,
                    blockheight INTEGER UNIQUE, 
                    blockheaderhash TEXT UNIQUE,
                    version INTEGER,
                    prev_blockheaderhash TEXT,
                    merkle_root_hash TEXT,
                    nTime INTEGER,
                    nBits TEXT,
                    nNonce INTEGER,

                    chainwork TEXT,

                    datafile TEXT NOT NULL,
                    datafile_offset INTEGER NOT NULL
                );
            """
            )
            cursor.execute("CREATE INDEX blockheight_index ON block(blockheight);")
            cursor.execute(
                "CREATE INDEX blockheaderhash_index ON block(blockheaderhash);"
            )
            self._conn.commit()
        cursor.close()

    def create_tx_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='tx';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE tx(
                    id INTEGER PRIMARY KEY,
                    txid TEXT,
                    wtxid TEXT,
                    version INTEGER,

                    blockheaderhash TEXT,
                    n INTEGER,
                    FOREIGN KEY(blockheaderhash) REFERENCES block(blockheaderhash)
                );
            """
            )
            cursor.execute("CREATE INDEX tx_txid_index ON tx(txid);")
            cursor.execute(
                "CREATE INDEX tx_blockheaderhash_index ON tx(blockheaderhash);"
            )
            self._conn.commit()
        cursor.close()

    def create_utxoset_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='utxoset';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE utxoset(
                    txid TEXT NOT NULL,
                    vout INTEGER NOT NULL,
                    value INTEGER,
                    scriptpubkey TEXT,
                    blockheaderhash TEXT NOT NULL,
                    FOREIGN KEY(blockheaderhash) REFERENCES block(blockheaderhash),
                    PRIMARY KEY (txid, vout)
                );
            """
            )
            self._conn.commit()
        cursor.close()

    def create_ordinal_range_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ordinal_range';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE ordinal_range (
                    id INTEGER PRIMARY KEY UNIQUE,
                    start INTEGER,
                    end INTEGER,

                    utxoset_txid TEXT,
                    utxoset_vout INTEGER,
                    FOREIGN KEY(utxoset_txid, utxoset_vout) REFERENCES utxoset(txid, vout) ON DELETE SET NULL
                );
                """
            )
            self._conn.commit()
        cursor.close()

    def add_tx(
        self,
        txid: str,
        blockheaderhash: str,
        n: int,
        cursor: Optional[Cursor] = None,
    ):
        """
        Create a new tx row in index db
        Args:
            txid: str, transaction id
            blockheaderhash: str, block header hash for the block this tx is in
            n: int, tx index in block
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        cursor.execute(
            f"INSERT INTO tx (txid, blockheaderhash, n) VALUES ('{txid}', '{blockheaderhash}', {n});"
        )
        if ephemeral_cursor:
            self._conn.commit()
            cursor.close()

    def remove_tx(
        self,
        txid: str,
        blockheaderhash: str,
        cursor: Optional[Cursor] = None,
    ):
        """
        Remove tx from tx table
        Args:
            txid: str, transaction id (big endian)
            blockheaderhash: str, block header hash for the block this tx is in
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        cursor.execute(
            f"DELETE FROM tx WHERE txid='{txid}' and blockheaderhash='{blockheaderhash}';"
        )
        if ephemeral_cursor:
            self._conn.commit()
            cursor.close()

    def get_tx(
        self,
        txid: str,
        cursor: Optional[Cursor] = None,
    ) -> dict:
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        res = cursor.execute(
            f"SELECT txid, blockheaderhash, n FROM tx WHERE txid='{txid}';"
        )
        result = res.fetchone()
        if ephemeral_cursor:
            cursor.close()
        return (
            {
                "txid": result[0],
                "blockheaderhash": result[1],
                "n": result[2],
            }
            if result
            else {}
        )

    def delete_block(self, blockheaderhash: str, cursor: Optional[Cursor] = None):
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        cursor.execute(f"DELETE FROM block WHERE blockheaderhash='{blockheaderhash}';")
        if ephemeral_cursor:
            self._conn.commit()
            cursor.close()

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
        chainwork: str,
        datafile: str,
        datafile_offset: int,
        cursor: Optional[Cursor] = None,
    ):
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
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
                chainwork,
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
                '{chainwork}',
                '{datafile}',
                {datafile_offset}
            );
        """
        cursor.execute(cmd)
        if ephemeral_cursor:
            self._conn.commit()
            cursor.close()

    def get_blockchain_height(
        self, cursor: Optional[Cursor] = None
    ) -> Union[int | None]:
        """
        Get blockchain height according to block index
        Returns:
            blockheight: int, or None if no block row found from query
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        res = cursor.execute(
            "SELECT blockheight FROM block ORDER BY blockheight DESC LIMIT 1;"
        )
        result = res.fetchone()
        if ephemeral_cursor:
            cursor.close()
        return result[0] if result else None

    def count_blocks(self, cursor: Optional[Cursor] = None) -> int:
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        res = cursor.execute("SELECT COUNT(*) FROM block;").fetchone()[0]
        if ephemeral_cursor:
            cursor.close()
        return int(res)

    def get_block(
        self,
        blockheight: Optional[int] = None,
        blockheaderhash: Optional[str] = None,
        cursor: Optional[Cursor] = None,
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
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        if blockheight is not None and blockheaderhash is not None:
            raise ValueError(
                "both blockheight and blockheaderhash should not be specified"
            )
        if blockheight is None and blockheaderhash is None:
            raise ValueError("blockheight or blockheaderhash must be provided")

        if blockheight is not None:
            res = cursor.execute(
                f"SELECT * FROM block WHERE blockheight='{blockheight}';"
            )
        else:
            # blockheaderhash is not None
            res = cursor.execute(
                f"SELECT * FROM block WHERE blockheaderhash='{blockheaderhash}';"
            )

        result = res.fetchone()
        if ephemeral_cursor:
            cursor.close()
        return (
            {
                "id": int(result[0]),
                "blockheight": int(result[1]),
                "blockheaderhash": result[2],
                "version": int(result[3]),
                "prev_blockheaderhash": result[4],
                "merkle_root_hash": result[5],
                "nTime": int(result[6]),
                "nBits": result[7],
                "nNonce": int(result[8]),
                "chainwork": result[9],
                "datafile": result[10],
                "datafile_offset": int(result[11]),
            }
            if result
            else None
        )

    def get_utxoset(
        self, txid: str, vout: int, cursor: Optional[Cursor] = None
    ) -> Union[dict, None]:
        """
        Get utxoset table entry, for given txid and vout, if exists, else None
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        res = cursor.execute(
            f"SELECT * FROM utxoset WHERE txid='{txid}' AND vout='{vout}';"
        )
        result = res.fetchone()
        if ephemeral_cursor:
            cursor.close()
        return (
            {
                "txid": result[1],
                "vout": int(result[2]),
                "value": int(result[3]),
                "scriptpubkey": result[4],
                "blockheaderhash": result[5],
            }
            if result
            else None
        )

    def remove_from_utxoset(
        self,
        txid: str,
        vout: int,
        index_ordinals: bool = False,
        cursor: Optional[Cursor] = None,
    ) -> Tuple[Tuple[int, int]]:
        """
        Remove row from utxoset
        Args:
            txid: str, transaction id
            vout: int, output number
            index_ordinals: bool, whether to index ordinals
        Return:
            ordinal ranges removed e.g. ((0, 16), (420, 690), ...)
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
        if index_ordinals:
            ordinal_ranges = cursor.execute(
                "SELECT start, end FROM ordinal_range WHERE utxoset_txid=? AND utxoset_vout=?;",
                (txid, vout),
            ).fetchall()
        utxo_blockheaderhash = cursor.execute(
            "SELECT blockheaderhash FROM utxoset WHERE txid=? AND vout=?;",
            (txid, vout),
        ).fetchone()[0]
        cursor.execute("DELETE FROM utxoset WHERE txid=? AND vout=?;", (txid, vout))
        if ephemeral_cursor:
            self._conn.commit()
            cursor.close()
        return ordinal_ranges if index_ordinals else []

    def add_to_utxoset(
        self,
        txid: str,
        vout: int,
        blockheaderhash: str,
        ordinal_ranges: List[List[int]],
        index_ordinals: bool = False,
        replace: bool = False,
        cursor: Optional[Cursor] = None,
    ):
        """
        Add to utxo set
        Args:
            txid: str, transaction id
            vout: int, output number
            blockheaderhash: str, block header hash for the block this utxo is in
            ordinal_ranges: list, list of ordinal ranges contained in this utxo
            replace: bool, use INSERT OR REPLACE when adding utxo, defaults to False
            cursor: Optional[Cursor], optional Db cursor to use
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
        if replace:
            cursor.execute(
                "INSERT OR REPLACE INTO utxoset (txid, vout, blockheaderhash) VALUES (?, ?, ?);",
                (txid, vout, blockheaderhash),
            )
        else:
            cursor.execute(
                "INSERT INTO utxoset (txid, vout, blockheaderhash) VALUES (?, ?, ?);",
                (txid, vout, blockheaderhash),
            )
        if index_ordinals:
            cursor.executemany(
                "INSERT INTO ordinal_range(start, end, utxoset_txid, utxoset_vout) VALUES (?, ?, ?, ?);",
                [(start, end, txid, vout) for start, end in ordinal_ranges],
            )
        if ephemeral_cursor:
            self._conn.commit()
            cursor.close()

    def find_blockheaderhash_for_utxo(
        self, txid: str, cursor: Optional[Cursor] = None
    ) -> Union[str, None]:
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        res = cursor.execute(f"SELECT blockheaderhash FROM tx WHERE txid='{txid}';")
        result = res.fetchone()
        if ephemeral_cursor:
            cursor.close()
        return result[0] if result else None


class PeerDb:
    def __init__(self, db_filepath: str):
        self._conn = sqlite3.connect(db_filepath, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.execute("PRAGMA busy_timeout=1000;")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._conn.close()

    def create_tables(self):
        self.create_peer_table()

    def create_peer_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='peer';"
        ).fetchone()
        if not query:
            cursor.execute(
                """
                CREATE TABLE peer(
                    host TEXT,
                    port INTEGER,

                    protocol_version INTEGER,
                    services INTEGER,
                    user_agent TEXT,
                    start_height INTEGER,

                    feefilter_feerate INTEGER,
                    sendcmpct_announce BOOLEAN,
                    sendcmpct_version INTEGER,
                    sendheaders BOOLEAN DEFAULT 0,

                    data BLOB,

                    time INTEGER,
                    type TEXT,

                    PRIMARY KEY (host, port)
                );
            """
            )
            self._conn.commit()
        cursor.close()

    def get_peer(self, host: str, port: int, cursor: Optional[Cursor] = None) -> dict:
        """
        Get peer data from db for a given host and port
        Args:
            host: str, host
            port: int, port
        Returns:
            dict, peer data
        """
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        result = cursor.execute(
            f"SELECT * FROM peer WHERE host='{host}' AND port={port};"
        ).fetchone()
        if ephemeral_cursor:
            cursor.close()
        return (
            {
                "host": result[0],
                "port": result[1],
                "protocol_version": result[2],
                "services": result[3],
                "user_agent": result[4],
                "start_height": result[5],
            }
            if result
            else {}
        )

    def save_peer(self, host: str, port: int, cursor: Optional[Cursor] = None):
        ephemeral_cursor = False
        if not cursor:
            ephemeral_cursor = True
            cursor = self._conn.cursor()
        cursor.execute(f"INSERT INTO peer (host, port) VALUES ('{host}', {port});")
        if ephemeral_cursor:
            cursor.close()
            self._conn.commit()
