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
import sqlite3
import time
import traceback
from asyncio import Event, StreamReader, StreamWriter
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from ipaddress import ip_address
from threading import Thread, Lock
from typing import List, Optional, Tuple, Union

import bits.blockchain
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
    user_agent_byte = versionpayload_[80]
    if user_agent_byte < 253:
        user_agent_len = user_agent_byte
        parsed_payload["user_agent_bytes"] = user_agent_len
    elif user_agent_byte == 253:
        user_agent_len = int.from_bytes(versionpayload_[81:83], "little")
        parsed_payload["user_agent_bytes"] = user_agent_len
    elif user_agent_byte == 254:
        user_agent_len = int.from_bytes(versionpayload_[81:85], "little")
        parsed_payload["user_agent_bytes"] = user_agent_len
    elif user_agent_byte == 255:
        user_agent_len = int.from_bytes(versionpayload_[81:89], "little")
        parsed_payload["user_agent_bytes"] = user_agent_len
    # parse rest of payload
    if user_agent_len == 0:
        parsed_payload["start_height"] = int.from_bytes(
            versionpayload_[81:85], "little"
        )
        if versionpayload_[85] == 1:
            parsed_payload["relay"] = True
        elif versionpayload_[85] == 0:
            parsed_payload["relay"] = False

        if versionpayload_[86:]:
            raise ValueError(
                f"parse error, data longer than expected: {len(versionpayload_)}"
            )
    else:
        parsed_payload["user_agent"] = versionpayload_[81 : 81 + user_agent_len].decode(
            "utf8"
        )
        parsed_payload["start_height"] = int.from_bytes(
            versionpayload_[81 + user_agent_len : 81 + user_agent_len + 4], "little"
        )
        if versionpayload_[81 + user_agent_len + 4] == b"\x01":
            parsed_payload["relay"] = True
        elif versionpayload_[81 + user_agent_len + 4] == b"\x00":
            parsed_payload["relay"] = False

        if versionpayload_[81 + user_agent_len + 4 + 1 :]:
            raise ValueError(
                f"parse error, data longer than expected: {len(versionpayload_)}"
            )

    return parsed_payload


def version_payload(
    start_height: int,
    addr_recv_port: int,
    addr_trans_port: int,
    protocol_version: int = 70015,
    services: int = NODE_NETWORK,
    relay: bool = True,
    user_agent: bytes = BITS_USER_AGENT,
) -> bytes:
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
    msg += b"\x01" if relay else b"\x00"
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
    protocol_version: int = 70015,
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


class Peer:
    def __init__(self, host: Union[str, bytes], port: int, network: str, datadir: str):
        self.host = host
        self.port = port
        self.datadir = datadir

        self._id: Union[int | None] = None

        self._ibd = False

        if network.lower() == "mainnet":
            self.magic_start_bytes = bits.constants.MAINNET_START
        elif network.lower() == "testnet":
            self.magic_start_bytes = bits.constants.TESTNET_START
        elif network.lower() == "regtest":
            self.magic_start_bytes = bits.constants.REGTEST_START
        else:
            raise ValueError(f"network not recognized: {network}")

        self._last_recv_msg_time: float = None

        self.reader: StreamReader = None
        self.writer: StreamWriter = None

        self._data = None
        self._addr_processing_queue = asyncio.Queue()

        self.inventories = []
        self._header_processing_queue = deque([])
        self.orphan_blocks = {}
        self._pending_getdata_requests = deque([])
        self._pending_getblocks_request = None
        self._pending_getheaders_request = None

        self.exit_event = Event()

    def __repr__(self):
        return f"peer(id={self._id}, host='{self.host}', port={self.port})"

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
            log.trace(f"raw message bytes: {message_bytes.hex()}")
        except ConnectionResetError as err:
            log.error(err)
            log.info(f"connection reset while sending {command} to {self}.")
            self.exit_event.set()
            log.info(f"{self} exit event set")


class Node:
    def __init__(
        self,
        seeds: List[str],
        datadir: str,
        network: str,
        log_level: str = "debug",
        protocol_version: int = 70015,
        services: int = NODE_NETWORK,
        relay: bool = True,
        user_agent: bytes = BITS_USER_AGENT,
        max_outgoing_peers: int = 2,
        connection_timeout: int = 5,
        download_headers: bool = True,
        download_blocks: bool = True,
        index_ordinals: bool = False,
        assumevalid: int = 0,
    ):
        """
        bits P2P node

        Args:
            seeds: list[str], list of seed nodes to connect to, <host:port> e.g. ["127.0.0.1:18443",]
            datadir: str, data directory, block data will be stored in <datadir>/blocks
            network: str, network, e.g. "mainnet", "testnet", or "regtest", sets magic start bytes
            protocol_version: int
            services: int
            relay: bool
            user_agent: bytes
        """
        self._assumevalid = assumevalid
        self._index_ordinals = index_ordinals
        self.download_headers = download_headers
        self.download_blocks = download_blocks
        self.max_outgoing_peers = max_outgoing_peers
        self.connection_timeout = connection_timeout
        self.seeds = seeds
        datadir = os.path.expanduser(datadir)
        if not os.path.exists(datadir):
            os.makedirs(datadir)
        self.datadir = datadir
        blocksdir = os.path.join(self.datadir, "blocks")
        if not os.path.exists(blocksdir):
            os.mkdir(blocksdir)
        self.blocksdir = blocksdir
        self.protocol_version = protocol_version
        self.services = services
        self.relay = relay
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
                self.db.add_tx(genesis_coinbase_tx["txid"], gb["blockheaderhash"], 0, 1)
                self.db.add_to_utxoset(
                    genesis_coinbase_tx["txid"],
                    0,
                    1,
                    [(0, bits.blockchain.block_reward(0) - 1)],
                    index_ordinals=self._index_ordinals,
                )

        self.message_queue = asyncio.Queue()
        self._ibd: bool = False

        self._block_processing_queue = deque([])
        self._block_cache: dict[str, dict] = {}
        # block cache e.g.
        # {"<blockheaderhash": {"time": <time:int>, "data": <block:Block>}, ...}
        # upon each entry, record time stamp,
        # and remove oldest entry if greater than MAX_BLOCK_CACHE_SIZE

        self._mempool = []

        self.peers: list[Peer] = []

        self.exit_event = Event()

        self._thread_pool_executor = ThreadPoolExecutor(max_workers=5)

    ### handlers ###
    def handle_feefilter_command(self, peer: Peer, command: bytes, payload: bytes):
        payload = parse_feefilter_payload(payload)
        with self._thread_lock:
            self.db.save_peer_data(peer._id, {"feefilter": payload})
            cursor = self.db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET feefilter_feerate={payload['feerate']} WHERE id={peer._id};"
            )
            self.db._conn.commit()
            cursor.close()

    def handle_sendheaders_command(self, peer: Peer, command: bytes, payload: bytes):
        with self._thread_lock:
            self.db.save_peer_data(peer._id, {"sendheaders": 1})

    def handle_reject_command(self, peer: Peer, command: bytes, payload: bytes):
        """
        https://developer.bitcoin.org/reference/p2p_networking.html#reject
        """
        reject = parse_reject_payload(payload)
        log.debug(reject)

    async def handle_addr_command(self, peer: Peer, command: bytes, payload: bytes):
        payload = parse_addr_payload(payload)
        addrs = payload["addrs"]
        await peer._addr_processing_queue.put(addrs)
        log.debug(
            f"{len(addrs)} network addrs to queue for {peer}. queue size: {peer._addr_processing_queue.qsize()}"
        )

    def handle_inv_command(self, peer: Peer, command: bytes, payload: bytes):
        parsed_payload = parse_inv_payload(payload)
        count = parsed_payload["count"]
        inventories = parsed_payload["inventory"]

        if self._ibd:
            # ignore non msg_block inventories during ibd
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
        tx = Tx(payload)

        tx_in_mempool = next(
            filter(
                lambda tx_: tx_["txid"] == tx["txid"],
                self._mempool,
            ),
            None,
        )
        if not tx_in_mempool:
            self._mempool.append(tx)
            log.info(
                f"tx(txid={tx['txid']}) added to mempool. total mempool txns: {len(self._mempool)}"
            )

        pending_getdata_request_match = next(
            filter(
                lambda inv: inv["type_id"] == "MSG_TX" and inv["hash"] == tx["txid"],
                peer._pending_getdata_requests,
            ),
            None,
        )
        if pending_getdata_request_match:
            peer._pending_getdata_requests.remove(pending_getdata_request_match)
            pending_getdata_request_match.pop("time")
            pending_getdata_request_match.pop("retries")
            peer.inventories.remove(pending_getdata_request_match)

    def handle_block_command(self, peer: Peer, command: bytes, payload: bytes):
        block = Block(payload)

        self._block_processing_queue.append(block)
        log.debug(
            f"block {block['blockheaderhash']} from {peer} added to processing queue. total blocks in queue: {len(self._block_processing_queue)}"
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
            self.db.save_peer_data(peer._id, {"sendcmpct": payload})
            cursor = self.db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET sendcmpct_announce={payload['announce']}, sendcmpct_version={payload['version']} WHERE id={peer._id};"
            )
            self.db._conn.commit()
            cursor.close()

    async def handle_getheaders_command(
        self, peer: Peer, command: bytes, payload: bytes
    ):
        payload = parse_getheaders_payload(payload)
        log.warning(f"no action taken for getheader command with payload {payload}")
        # await peer.send_command(b"headers")

    async def handle_ping_command(self, peer: Peer, command: bytes, payload: bytes):
        """
        Handle ping command by sending a 'pong' message
        """
        payload = parse_ping_payload(payload)
        await peer.send_command(b"pong", ping_payload(payload["nonce"]))

    async def connect_peers(self, peers: List[Peer], timeout: int = None):
        """
        Connect peers and schedule tasks
        Args:
            peers: list[Peer], list of outgoing peers to connect to
            timeout: Optional[int], connection timeout, defaults to self.connection_timeout
        Returns:
            peers which were successfully connected w successful version handshake
        """
        connected_peers = []
        if timeout is None:
            timeout = self.connection_timeout
        for peer in peers:
            if len(self.peers) >= self.max_outgoing_peers:
                log.warning(
                    f"connect_peers loop exit. max_outgoing_peers already reached"
                )
                break
            log.trace(f"connecting to {peer}...")
            try:
                await asyncio.wait_for(peer.connect(), timeout)
            except Exception as err:
                log.error(f"error attempting to connect to {peer} - {err}")
                continue
            log.info(f"connected to {peer}")
            peer_id = self.db.get_peer(peer.host, peer.port)
            if not peer_id:
                peer_id = self.db.save_peer(peer.host, peer.port)
                # save hardcoded genesis block to blockheader table for peer
                genesis_blockheader = Blockheader(
                    genesis_block(network=self.network)[:80]
                )
                with self._thread_lock:
                    self.db.save_blockheader(
                        0,
                        genesis_blockheader["blockheaderhash"],
                        genesis_blockheader["version"],
                        genesis_blockheader["prev_blockheaderhash"],
                        genesis_blockheader["merkle_root_hash"],
                        genesis_blockheader["nTime"],
                        genesis_blockheader["nBits"],
                        genesis_blockheader["nNonce"],
                        bits.blockchain.new_chainwork(
                            "0", genesis_blockheader["nBits"]
                        ),
                        peer_id,
                    )
                peer._id = peer_id
                log.info(f"{peer} saved to db.")
            peer._id = peer_id
            try:
                connect_to_peer_task = asyncio.create_task(self.connect_to_peer(peer))
                await asyncio.wait_for(connect_to_peer_task, timeout)
            except Exception as err:
                traceback.format_exc()
                log.error(
                    f"exception occurred while attempting to complete connection handshake for {peer} - {err}"
                )
                self.db.remove_peer(peer._id)
                log.info(f"{peer} removed from db")
            else:
                version_data = connect_to_peer_task.result()
                # TODO: verify version data more rigorously?
                # nonce, timestamp, recv / trans addrs services
                log.debug(f"{peer} version payload: {version_data}")
                self.db.save_peer_data(peer._id, {"version": version_data})
                cursor = self.db._conn.cursor()
                cursor.execute(
                    f"UPDATE peer SET protocol_version={version_data['protocol_version']}, services={version_data['services']}, user_agent='{version_data['user_agent']}', start_height='{version_data['start_height']}' WHERE id={peer._id};"
                )
                self.db._conn.commit()
                log.info(f"version data for {peer} saved to db")
                cursor.execute(f"UPDATE peer SET is_connected=1 WHERE id={peer._id};")
                self.db._conn.commit()
                cursor.close()
                self.peers.append(peer)
                connected_peers.append(peer)
                asyncio.create_task(self.outgoing_peer_recv_loop(peer))
                # asyncio.create_task(peer.send_command(b"getaddr"))
                # asyncio.create_task(self.process_addrs(peer))
        return connected_peers

    async def connect_to_peer(self, peer: Peer) -> dict:
        """
        Connect to peer by performing version / verack handshake
        https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
        Args:
            peer: Peer, peer to connect to
        Returns:
            version_data: dict, parsed version payload from peer
        """
        trans_sock = peer.writer.transport.get_extra_info("socket")
        local_host, local_port = trans_sock.getsockname()
        versionp = version_payload(
            0,
            peer.port,
            local_port,
            protocol_version=self.protocol_version,
            services=self.services,
            relay=self.relay,
            user_agent=self.user_agent,
        )
        await peer.send_command(b"version", versionp)

        # wait for version message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"version", f"expected version command not {command}"

        # save version payload peer data
        version_data = parse_payload(command, payload)
        log.info(f"parsed version payload for {peer}")

        # send verack
        await peer.send_command(b"verack")

        # wait for verack message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"verack", f"expected verack command, not {command}"

        log.info(f"connection handshake established for {peer}")
        return version_data

    async def outgoing_peer_recv_loop(self, peer: Peer, msg_timeout: int = 15):
        """
        Args:
            msg_timeout: int, sec to wait before timing out recv_msg and looping until exit_event has been set
        """
        loop = asyncio.get_running_loop()
        PEER_INACTIVITY_TIMEOUT = 5400  # 90 minutes
        while not peer.exit_event.is_set():
            try:
                start_bytes, command, payload = await asyncio.wait_for(
                    peer.recv_msg(), int(msg_timeout)
                )
            except asyncio.TimeoutError as err:
                if time.time() - peer._last_recv_msg_time > PEER_INACTIVITY_TIMEOUT:
                    peer.exit_event.set()
                    log.info(f"peer inactivity timeout reached. {peer} exit event set.")
                log.trace(f"{peer} recv_msg timeout.")
            except ShutdownException as err:
                log.info(f"shutdown except raised during recv_msg for {peer} - {err}")
            else:
                await self.message_queue.put((peer, command, payload))
            await asyncio.sleep(0)
        log.info(f"exiting peer recv loop for {peer}")
        await peer.close()
        log.info(f"{peer} socket is closed.")
        self.peers.remove(peer)
        await loop.run_in_executor(
            self._thread_pool_executor, self.set_peer_connected, peer._id, False
        )

    def set_peer_connected(self, peer_id: int, is_connected: bool):
        """
        Set peer is_connected to True or False
        Args:
            peer_id: int
            is_connected: bool
        """
        with self._thread_lock:
            cursor = self.db._conn.cursor()
            cursor.execute(
                f"UPDATE peer SET is_connected={1 if is_connected else 0} WHERE id={peer_id};"
            )
            self.db._conn.commit()
            cursor.close()

    def handle_incoming_peer(self):
        return

    async def incoming_peer_server(self):
        server = await asyncio.start_server(self.handle_incoming_peer, "0.0.0.0", 10101)
        async with server:
            await server.serve_forever()

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
            else:
                handler = getattr(self, f"handle_{command.decode('utf8')}_command")
                await loop.run_in_executor(
                    self._thread_pool_executor, handler, peer, command, payload
                )
            await asyncio.sleep(0)
        log.trace("message handler loop exited")

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
        # check datadir for internal consistency
        dat_filenames = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        dat_filename = dat_filenames[-1]
        blocks = self.parse_dat_file(os.path.join(self.blocksdir, dat_filename))
        if not blocks:
            raise AssertionError(f"{dat_filename} is empty")
        last_block = blocks[-1]

        number_of_blocks_on_disk = self.count_blocks()
        number_of_blocks_in_index = self.db.count_blocks()

        if number_of_blocks_on_disk != number_of_blocks_in_index:
            raise AssertionError(
                f"number of blocks on disk ({number_of_blocks_on_disk}) does not equal the number of blocks in index ({number_of_blocks_in_index})."
            )

        else:
            # block on disk == blocks in index,
            # do further sanity checks
            blockheight = self.db.get_blockchain_height()
            last_block_index = self.db.get_block(blockheight=blockheight)
            blockheaderhash_calc = bits.crypto.hash256(last_block[:80])[::-1].hex()
            if blockheaderhash_calc != last_block_index["blockheaderhash"]:
                raise AssertionError(
                    "last blockheaderhash in index does not match last block on disk"
                )

    def run(self, reindex: bool = False):
        asyncio.run(self.main(reindex=reindex), debug=True)

    def start(self, reindex: bool = False):
        self.exit_event.clear()
        self._thread = Thread(target=self.run, kwargs={"reindex": reindex})
        self._thread.start()

    def stop(self):
        log.info("stopping node gracefully...")
        for peer in self.peers:
            peer.exit_event.set()
            log.info(f"peer {peer._id} exit event set")
        self.exit_event.set()
        log.info("node exit event set")

    async def main(self, reindex: bool = False):
        if not os.path.exists(self.index_db_filepath):
            reindex = True
        if reindex:
            self.db._conn.close()
            os.remove(self.index_db_filepath)
            self.db = Db(self.index_db_filepath)
            self.db.create_tables()
            self.rebuild_index()
        else:
            self.startup_checks()

        # parse seeds into list of (host, port)
        seed_addrs = [
            (seed.split(":")[0], int(seed.split(":")[1])) for seed in self.seeds
        ]

        # gather peer addrs we've connected to before
        formerly_connected_peer_addrs = [
            (addr["host"], addr["port"]) for addr in self.db.get_peer_addrs(None)
        ]
        # peer_id None is implied to mean peer_addrs that our Node has actually connected to

        former_peer_addr_candidates = list(
            set(formerly_connected_peer_addrs) - set(seed_addrs)
        )
        peer_candidates = [
            Peer(addr[0], addr[1], self.network, self.datadir)
            for addr in seed_addrs + former_peer_addr_candidates
        ]

        connected_peers = await self.connect_peers(peer_candidates)
        # connected peers have been appended to self.peers,
        # headers_sync, outgoing_peer_recv_loop tasks created, etc.

        if connected_peers:
            blockheight = self.db.get_blockchain_height()

            # choose a peer as sync node
            # if blockchain is 144 blocks behind peer (~24 hr) enter ibd
            sync_node = self.peers[0]
            sync_node_version_data = self.db.get_peer_data(sync_node._id, "version")
            self.sync_node_start_height = sync_node_version_data["start_height"]
            if sync_node_version_data["start_height"] - blockheight > 144:
                log.info(
                    f"local blockchain is behind sync node {sync_node} by {sync_node_version_data['start_height'] - blockheight} blocks. Entering IBD..."
                )
                self._ibd = True
                if self.download_headers:
                    for peer in connected_peers:
                        peer._ibd = True
                        asyncio.create_task(self.request_headers(peer))
                        asyncio.create_task(self.process_headers(peer))
                if self.download_blocks:
                    asyncio.create_task(self.request_block_inventories(sync_node))
                    asyncio.create_task(self.request_blocks(sync_node))
                    asyncio.create_task(self.process_blocks())

            asyncio.create_task(self.message_handler_loop())
            # asyncio.create_task(self.request_tx(sync_node))
        else:
            log.error("couldn't connect to peers")

        tasks = asyncio.all_tasks()
        tasks.remove(asyncio.current_task())
        await asyncio.gather(*tasks)
        log.trace("main exit")

    async def process_addrs(self, peer: Peer):
        """
        Process the addrs peer has received,
          by attempting to connect if applicable, then saving to db
        """
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():
            try:
                addrs = await asyncio.wait_for(peer._addr_processing_queue.get(), 1.0)
            except asyncio.TimeoutError:
                continue

            # remove addrs that have already been added to db for this peer
            existing_addrs_set = set(
                [
                    (addr["host"], addr["port"])
                    for addr in self.db.get_peer_addrs(peer._id)
                ]
            )
            addrs = [
                addr
                for addr in addrs
                if (addr["host"], addr["port"]) not in existing_addrs_set
            ]

            if len(self.peers) < self.max_outgoing_peers:
                for addr in addrs:
                    if (addr["host"], addr["port"]) in [
                        (peer_.host, peer_.port) for peer_ in self.peers
                    ]:
                        # don't connect to peers we've already connected to
                        # just save to db for this peer
                        await loop.run_in_executor(
                            self._thread_pool_executor, self.save_addr, addr, peer._id
                        )
                        continue
                    potential_peer = Peer(
                        addr["host"], addr["port"], self.network, self.datadir
                    )

                    connected_peers = await self.connect_peers([potential_peer])
                    if not connected_peers:
                        log.debug(f"failed to connect to {potential_peer}")
                        await loop.run_in_executor(
                            self._thread_pool_executor, self.save_addr, addr, peer._id
                        )
                    else:
                        log.info(
                            f"connected to {potential_peer}. total outgoing connected peers: {len(self.peers)}"
                        )
                        await loop.run_in_executor(
                            self._thread_pool_executor, self.save_addr, addr, peer._id
                        )
                        addr["time"] = int(time.time())
                        await loop.run_in_executor(
                            self._thread_pool_executor, self.save_addr, addr, None
                        )
            else:
                # if we're already at max outgoing peers, just save to db
                for addr in addrs:
                    await loop.run_in_executor(
                        self._thread_pool_executor, self.save_addr, addr, peer._id
                    )
            await asyncio.sleep(0)
        log.trace(f"process_addrs loop exit for {peer}")

    def save_addr(self, addr: dict, peer_id: int):
        time_ = addr["time"]
        host = addr["host"]
        port = addr["port"]
        services = addr["services"]

        cols = (
            "(host, port, time, services, peer_id)"
            if peer_id is not None
            else "(host, port, time, services)"
        )
        vals = (
            f"('{host}', {port}, {time_}, {services}, {peer_id})"
            if peer_id is not None
            else f"('{host}', {port}, {time_}, {services})"
        )
        sql_ = f"INSERT INTO addr {cols} VALUES {vals};"
        with self._thread_lock:
            cursor = self.db._conn.cursor()
            cursor.execute(sql_)
            self.db._conn.commit()
            cursor.close()
        log.debug(
            f"network addr info for {addr['host']}:{addr['port']} saved to db for peer(id={peer_id})."
        )

    async def request_headers(self, peer: Peer):
        while (
            peer._ibd and not self.exit_event.is_set() and not peer.exit_event.is_set()
        ):
            if (
                not peer._pending_getheaders_request
                and not peer._header_processing_queue
            ):
                cursor = self.db._conn.cursor()
                best_blockheaderhash = cursor.execute(
                    f"SELECT blockheaderhash FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 1"
                ).fetchone()[0]
                cursor.close()
                peer._pending_getheaders_request = best_blockheaderhash
                await peer.send_command(
                    b"getheaders",
                    getblocks_payload([bytes.fromhex(best_blockheaderhash)[::-1]]),
                )
            await asyncio.sleep(1)
        log.info(f"request_headers loop exit for {peer}")

    async def process_headers(self, peer: Peer):
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():
            if peer._header_processing_queue:
                blockheader = peer._header_processing_queue[0]
                await loop.run_in_executor(
                    self._thread_pool_executor, self.process_header, peer, blockheader
                )
                # pop from queue after header validation completes,
                #  to avoid race condition where we request a duplicate header in request_headers
                _ = peer._header_processing_queue.popleft()
            await asyncio.sleep(0)
        log.info(f"process_headers loop exit for {peer}")

    def process_header(self, peer: Peer, blockheader: Union[Blockheader, Bytes, bytes]):
        cursor = self.db._conn.cursor()
        current_blockheader_height = cursor.execute(
            f"SELECT blockheight FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 1;"
        ).fetchone()[0]
        cursor.close()
        current_blockheader_index_data = self.db.get_blockheader(
            peer._id, blockheight=current_blockheader_height
        )

        blockheader_height = current_blockheader_height + 1

        if not bits.blockchain.check_blockheader(blockheader, network=self.network):
            raise CheckBlockError(
                f"blockheader {blockheader['blockheaderhash']} from {peer} check failed"
            )

        if self.db.get_blockheader(
            peer._id, blockheaderhash=blockheader["blockheaderhash"]
        ):
            raise AcceptBlockError(
                f"blockheader hash {blockheader['blockheaderhash']} already found in current blockheaders for {peer}"
            )

        if (
            blockheader["prev_blockheaderhash"]
            != current_blockheader_index_data["blockheaderhash"]
        ):
            raise AcceptBlockError(
                f"blockheader {blockheader['blockheaderhash']} from {peer} prev blockheader hash ({blockheader['prev_blockheaderhash']}) does not match current blockheader hash ({current_blockheader_index_data['blockheaderhash']})"
            )

        # check nbits is set correctly
        next_nbits_set = self.get_next_nbits(blockheader, peer_id=peer._id)
        if blockheader["nBits"] not in next_nbits_set:
            raise AcceptBlockError(
                f"blockheader {blockheader['blockheaderhash']} from {peer} nBits {blockheader['nBits']} is not in {next_nbits_set}"
            )

        cursor = self.db._conn.cursor()
        _query_results = cursor.execute(
            f"SELECT nTime FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 11;"
        ).fetchall()
        cursor.close()
        last_11_times = [result[0] for result in _query_results]
        median_time_ = bits.blockchain.median_time(last_11_times)
        if blockheader["nTime"] <= median_time_:
            raise AcceptBlockError(
                f"blockheader {blockheader['blockheaderhash']} from {peer} nTime {blockheader['nTime']} is not strictly greater than the median time {median_time_}"
            )

        current_time = time.time()
        if blockheader["nTime"] > current_time + 7200:
            raise AcceptBlockError(
                f"blockheader {blockheader['blockheaderhash']} from {peer} nTime {blockheader['nTime']} is more than two hours in the future {current_time + 7200}"
            )

        with self._thread_lock:
            new_blockheader_index_data = self.db.save_blockheader(
                blockheader_height,
                blockheader["blockheaderhash"],
                blockheader["version"],
                blockheader["prev_blockheaderhash"],
                blockheader["merkle_root_hash"],
                blockheader["nTime"],
                blockheader["nBits"],
                blockheader["nNonce"],
                bits.blockchain.new_chainwork(
                    current_blockheader_index_data["chainwork"], blockheader["nBits"]
                ),
                peer._id,
            )
        log.info(f"added blockheader {blockheader_height} to header chain for {peer}")

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

    async def request_block_inventories(self, peer: Peer):
        """
        Request block inventories via 'getblocks' from peer, during IBD

        Expected response of 2000 inventories until we get current
        """
        while self._ibd and not self.exit_event.is_set():
            block_inventories = list(
                filter(lambda inv: inv["type_id"] == "MSG_BLOCK", peer.inventories)
            )
            if (
                not block_inventories
                and not self._block_processing_queue
                and not peer._pending_getblocks_request
            ):
                current_block_height = self.db.get_blockchain_height()
                current_block_index_data = self.db.get_block(current_block_height)
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
            elif (
                peer._pending_getblocks_request
                and peer._pending_getblocks_request["time"] < time.time() - 60
            ):
                log.debug(
                    f"pending getblocks {peer._pending_getblocks_request} request expired."
                )
                peer._pending_getblocks_request = None
            else:
                log.trace(
                    f"request_block_inventories skip. len(block_inventories)={len(block_inventories)}, len(block_processsing_queue)={len(self._block_processing_queue)}, pending_getblocks_request={peer._pending_getblocks_request} "
                )
            await asyncio.sleep(1)
        log.trace("request_block_inventories loop exit")

    async def request_blocks(self, peer: Peer):
        """
        Request blocks via 'getdata' from peer, during IBD
        """
        MAX_BLOCKS_IN_QUEUE = 128
        while self._ibd and not self.exit_event.is_set():
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
                len(self._block_processing_queue) < MAX_BLOCKS_IN_QUEUE
                and block_inventories
                and not pending_getdata_requests
            ):
                inventory_list = block_inventories[
                    : MAX_BLOCKS_IN_QUEUE - len(self._block_processing_queue)
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
                        lambda req: req["time"] < time.time() - 60,
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
                    f"request_blocks loop skip. len(block_inventories)={len(block_inventories)}, len(pending_getdata_requests)={len(pending_getdata_requests)}"
                )
            await asyncio.sleep(1)
        log.trace("request_blocks loop exit")

    async def process_blocks(self):
        loop = asyncio.get_running_loop()
        while not self.exit_event.is_set():
            if self._block_processing_queue:
                block = self._block_processing_queue.popleft()
                await loop.run_in_executor(
                    self._thread_pool_executor, self.process_block, block
                )
            await asyncio.sleep(0)
        log.trace("exit process_blocks")

    def process_block(self, block: Block):
        try:
            self.accept_block(block)
        except PossibleOrphanError as err:
            log.debug(
                f"possible orphan block {block['blockheaderhash']}. discarding ..."
            )
        except PossibleForkError as err:
            raise err
            # best_peer = self.get_best_peer()
            # TODO: switch sync node to best peer, and rollback to common ancestor, if necessary
        except (CheckBlockError, AcceptBlockError) as err:
            raise err
        except ConnectBlockError as err:
            log.error(err)
            # revert
            current_block_index_data = self.db.get_block(
                blockheight=self.db.get_blockchain_height()
            )
            log.info(
                f"reverting changes to tx / utxoset via block {current_block_index_data['blockheight']} ..."
            )
            self.revert_block(current_block_index_data["blockheight"])
            log.info(
                f"changes to tx / utxoset via block {current_block_index_data['blockheight']} reverted in {self.index_db_filename}"
            )
            # delete last block & block index
            _deleted_block = self.delete_block()
            raise err

    def revert_block(self, blockheight: int):
        """
        Revert tx and utxoset changes for a block, given by revert table entries

        NOTE: This function does NOT delete the block data from disk nor the block index entry
        """
        block_id = self.db.get_block(blockheight=blockheight)["id"]
        revert_ops = self.db.get_block_revert(block_id)
        for op in revert_ops:
            if op["vout"] is None:
                # implied tx (not utxo) rollback
                self.db.remove_tx(op["txid"])
                log.debug(f"removed tx {op['txid']} from tx table")
            elif op["revert"]:
                # utxo rollback
                self.db.remove_from_utxoset(
                    op["txid"], op["vout"], index_ordinals=self._index_ordinals
                )
                log.debug(
                    f"removed utxo(txid={op['txid']}, vout={op['vout']}) from utxoset"
                )
            else:
                cursor = self.db._conn.cursor()
                tx_blockheaderhash = cursor.execute(
                    f"SELECT blockheaderhash FROM tx WHERE txid='{op['txid']}';"
                ).fetchone()[0]
                cursor.close()
                revert_block_id = self.db.get_block(blockheaderhash=tx_blockheaderhash)[
                    "id"
                ]
                self.db.add_to_utxoset(
                    op["txid"],
                    op["vout"],
                    revert_block_id,
                    json.loads(op["ordinal_ranges"]),
                    index_ordinals=self._index_ordinals,
                )
                log.debug(
                    f"added utxo(txid={op['txid']}, vout={op['vout']}) to utxoset with revert_block_id {revert_block_id}"
                )

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
            "progress": float(format(blockheight / start_height, "0.8f"))
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

    def get_node_info(self) -> Union[dict, None]:
        cursor = self.db._conn.cursor()
        peers = self.db.get_peers()
        # pop off peer addrs info
        for peer in peers:
            addrs = peer.pop("addrs")
            invs = peer.pop("invs")
            data = peer.pop("data")
            peer["addrs"] = len(addrs) if addrs else 0
            num_blockheaders = cursor.execute(
                f"SELECT COUNT(*) FROM blockheader WHERE peer_id={peer['id']};"
            ).fetchone()[0]
            peer["blockheaders"] = num_blockheaders
            best_blockheader = self.db.get_blockheader(
                peer["id"], blockheight=num_blockheaders - 1
            )
            peer["bestblockheaderhash"] = best_blockheader["blockheaderhash"]
            peer["bestblockheight"] = best_blockheader["blockheight"]
            peer["totalchainwork"] = best_blockheader["chainwork"]
        cursor.close()
        return {"peers": peers}

    def rebuild_index(self):
        """
        Rebuild block index db from the latest block index entry.

        Assumes that the blocks on disk are ordered by blockheight.
        """
        # block_i is our counter for the blockheight as indicated by the order of block data on disk
        block_i = 0

        log.info("rebuilding index...")
        dat_filenames = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        log.info(f"found {len(dat_filenames)} dat files in {self.blocksdir}")
        chainwork = "0000000000000000000000000000000000000000000000000000000000000000"
        for i, filename in enumerate(dat_filenames, start=1):
            log.info(f"parsing file {i} of {len(dat_filenames)} - {filename} ...")
            filepath = os.path.join(self.blocksdir, filename)
            with open(filepath, "rb") as dat_file:
                while not self.exit_event.is_set():
                    start_offset = dat_file.tell()
                    magic = dat_file.read(4)
                    if not magic:
                        break
                    assert magic == self.magic_start_bytes, "magic mismatch"
                    length = int.from_bytes(dat_file.read(4), "little")
                    block = Block(dat_file.read(length))
                    assert len(block) == length, "length mismatch"
                    chainwork = bits.blockchain.new_chainwork(chainwork, block["nBits"])
                    try:
                        log.debug(f"reindexing block {block['blockheaderhash']} ...")
                        self.accept_block(
                            block,
                            reindex=True,
                            rel_path=os.path.relpath(filepath, start=self.datadir),
                            start_offset=start_offset,
                        )
                    except Exception as err:
                        traceback.format_exc()
                        log.error(err)
                        raise err

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
        reindex: bool = False,
        rel_path: str = None,
        start_offset: int = None,
    ) -> bool:
        """
        Validate block as new tip and save block data and / or index and chainstate
        Args:
            block: Block | bytes, block data
            reindex: bool, True if this function if this is a reindex operation,
                meaning the block data won't be saved, but index and chainstate are still updated
            rel_path: str, relative path of block data, use if and only if reindex=True
            start_offset: int, start offset byte of block data in rel_path, use if and only if reindex=True
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
        if current_blockheight is None:
            # hack for reindexing
            # no block index exists yet for block 0
            # set "current_block_index_data" to be able to check and derive "new" chainwork
            current_block_index_data = {
                "blockheaderhash": "0000000000000000000000000000000000000000000000000000000000000000",
                "chainwork": "0000000000000000000000000000000000000000000000000000000000000000",
                "nBits": "1d00ffff",
                "nTime": 1231006505
                if self.network.lower() == "mainnet"
                else 1296688602,
            }
        else:
            current_block_index_data = self.db.get_block(
                blockheight=current_blockheight
            )

        proposed_blockheight = (
            current_blockheight + 1 if current_blockheight is not None else 0
        )
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

        # if prev blockhash field DOES match blockchain tip,
        # the next couple rules (nbits & timestamp checks)
        # must pass for the block to be considered valid

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

        # log.trace("get best peer")
        # # check if proposed block is in the most work chain,
        # best_peer_id = self.get_best_peer()
        # if best_peer_id is not None:
        #     cursor = self.db._conn.cursor()
        #     res = cursor.execute(
        #         f"SELECT blockheaderhash FROM blockheader WHERE peer_id={best_peer_id} AND blockheight={proposed_blockheight} AND blockheaderhash='{proposed_block['blockheaderhash']}';"
        #     ).fetchone()
        #     cursor.close()
        #     if not res:
        #         raise PossibleForkError(
        #             f"proposed block {proposed_block['blockheaderhash']} is not in the most work chain"
        #         )
        # log.trace("get best peer end")

        if not reindex:
            ### save block to disk and index db ###
            self.save_block(
                block,
                bits.blockchain.new_chainwork(
                    current_block_index_data["chainwork"], proposed_block["nBits"]
                ),
            )
        else:
            # TODO: this if/else code looks misleading
            with self._thread_lock:
                self.db.save_block(
                    proposed_blockheight,
                    proposed_block["blockheaderhash"],
                    proposed_block["version"],
                    proposed_block["prev_blockheaderhash"],
                    proposed_block["merkle_root_hash"],
                    proposed_block["nTime"],
                    proposed_block["nBits"],
                    proposed_block["nNonce"],
                    bits.blockchain.new_chainwork(
                        current_block_index_data["chainwork"], proposed_block["nBits"]
                    ),
                    rel_path,
                    start_offset,
                )
            log.info(f"block {proposed_blockheight} saved to {self.index_db_filename}")

        # cleanup proposed block variables
        del proposed_blockheight
        del proposed_block

        # now we update utxoset step-by-step during tx validation,

        current_blockheight = self.db.get_blockchain_height()
        current_block_index_data = self.db.get_block(blockheight=current_blockheight)

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
            self.db.add_tx(
                coinbase_tx["txid"],
                current_block["blockheaderhash"],
                0,
                current_block_index_data["id"],
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
                    + bits.blockchain.block_reward(current_blockheight)
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
                self.db.add_tx(
                    txn["txid"],
                    current_block["blockheaderhash"],
                    txn_i,
                    current_block_index_data["id"],
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
                cursor = self.db._conn.cursor()
                res = cursor.execute(
                    f"SELECT * FROM utxoset WHERE txid='{txin_txid}' AND vout={txin_vout};"
                ).fetchone()
                cursor.close()
                if not res:
                    raise ConnectBlockError(
                        f"utxo(txid='{txin_txid}', vout={txin_vout}) not found in utxoset"
                    )

                # get the utxo transaction in full
                utxo_block_index_data = self.db.get_block(
                    blockheaderhash=utxo_blockheaderhash,
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

                if current_blockheight >= self._assumevalid:
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
                        current_block_index_data["id"],
                        index_ordinals=self._index_ordinals,
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
                        current_block_index_data["id"],
                        utxo_ordinal_ranges,
                        index_ordinals=self._index_ordinals,
                    )
            block_ordinal_ranges += tx_ordinal_ranges

        max_block_reward = (
            bits.blockchain.block_reward(current_blockheight) + miner_tips
        )
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
                    current_block_index_data["id"],
                    utxo_ordinal_ranges,
                    index_ordinals=self._index_ordinals,
                )

        log.debug(
            f"processed all of {len(current_block['txns'])} txns in block {current_blockheight}."
        )
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
            current_block_index_data = self.db.get_blockheader(
                peer_id, blockheight=current_blockheight
            )
        else:
            next_block = Block(next_block)
            current_blockheight = self.db.get_blockchain_height()
            if current_blockheight is None:
                # hack, special case for reindexing, there is not block 0 index yet
                # just return with known starting nbits
                return set(["1d00ffff"])
            else:
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
                block_0_index_data = self.db.get_blockheader(
                    peer_id, current_blockheight - 2015
                )

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
        self.create_blockheader_table()
        self.create_utxoset_table()
        self.create_ordinal_range_table()
        self.create_peer_table()
        self.create_tx_table()
        self.create_revert_table()
        self.create_addr_table()

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
                    txid TEXT UNIQUE,
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
                    id INTEGER PRIMARY KEY,
                    txid TEXT,
                    vout INTEGER,
                    value INTEGER,
                    scriptpubkey TEXT,
                    FOREIGN KEY(txid) REFERENCES tx(txid)
                );
            """
            )
            cursor.execute("CREATE INDEX utxo_txid_vout_index ON utxoset(txid, vout);")
            self._conn.commit()
        cursor.close()

    def create_blockheader_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='blockheader';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE blockheader (
                    id INTEGER PRIMARY KEY,
                    blockheight INTEGER,

                    blockheaderhash TEXT,
                    version INTEGER,
                    prev_blockheaderhash TEXT,
                    merkle_root_hash TEXT,
                    nTime INTEGER,
                    nBits TEXT,
                    nNonce INTEGER,

                    chainwork TEXT,

                    peer_id INTEGER,
                    FOREIGN KEY(peer_id) REFERENCES peer(id)
                )
                """
            )
            cursor.execute(
                "CREATE INDEX blockheader_blockheaderhash_index ON blockheader(blockheaderhash, peer_id);"
            )
            cursor.execute(
                "CREATE INDEX blockheader_blockheight_index ON blockheader(blockheight, peer_id);"
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

                    utxoset_id INTEGER,
                    revert_block_id INTEGER,
                    FOREIGN KEY(utxoset_id) REFERENCES utxoset(id) ON DELETE SET NULL,
                    FOREIGN KEY(revert_block_id) REFERENCES revert(id) ON DELETE SET NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX ordinal_range_utxoset_id_index ON ordinal_range(utxoset_id);"
            )
            cursor.execute(
                "CREATE INDEX ordinal_range_revert_block_id_index ON ordinal_range(revert_block_id);"
            )
            self._conn.commit()
        cursor.close()

    def create_peer_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='peer';"
        ).fetchone()
        if not query:
            cursor.execute(
                """
                CREATE TABLE peer(
                    id INTEGER PRIMARY KEY,
                    host TEXT,
                    port INTEGER,
                    data TEXT,
                    addrs TEXT,
                    invs TEXT,

                    protocol_version INTEGER,
                    services INTEGER,
                    user_agent TEXT,
                    start_height INTEGER,

                    feefilter_feerate INTEGER,
                    sendcmpct_announce BOOLEAN,
                    sendcmpct_version INTEGER,

                    is_connected BOOLEAN
                );
            """
            )
            self._conn.commit()
        cursor.close()

    def create_revert_table(self):
        # revert table for block reorgs
        # block_id references the block for which this reversion is for (not the block that the utxo is contained in)
        #   note also that block_id references the primary key id, not blockheight nor blockheaderhash
        # id reflects the order in which the operation was made, thus reverse for the reversion order
        # revert is a boolean, True if revert, False if this is to be re-added
        # txid and vout refer to the utxo to be re-added or removed to utxoset
        # if vout is NULL, this indicates this txid itself to be removed from the tx table table during reversion,
        #   note that tx are never re-added during reversion
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='revert';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE revert(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    revert BOOLEAN DEFAULT 1,
                    txid TEXT,
                    vout INTEGER,
                    block_id INTEGER,
                    FOREIGN KEY(block_id) REFERENCES block(id)
                )
                """
            )
            cursor.execute("CREATE INDEX revert_block_id_index ON revert(block_id);")
            self._conn.commit()
        cursor.close()

    def create_addr_table(self):
        cursor = self._conn.cursor()
        query = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='addr';"
        ).fetchone()
        if not query:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                """
                CREATE TABLE addr(
                    id INTEGER PRIMARY KEY,
                    
                    host TEXT,
                    port INTEGER,
                    time INTEGER,
                    services INTEGER,

                    peer_id INTEGER,
                    FOREIGN KEY(peer_id) REFERENCES peer(id)
                );
            """
            )
            self._conn.commit()
        cursor.close()

    def save_blockheader(
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
        peer_id: int,
    ) -> dict:
        cursor = self._conn.cursor()
        cursor.execute(
            f"""
            INSERT INTO blockheader (
                blockheight, blockheaderhash, version, prev_blockheaderhash, merkle_root_hash, nTime, nBits, nNonce, chainwork, peer_id
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
                {peer_id}
            );
        """
        )
        self._conn.commit()
        cursor.close()
        new_blockheader_dict = self.get_blockheader(peer_id, blockheight=blockheight)
        return new_blockheader_dict

    def get_blockheader(
        self,
        peer_id: int,
        blockheight: Optional[int] = None,
        blockheaderhash: Optional[str] = None,
    ) -> Union[dict, None]:
        """
        Get the blockheader row data, as a dictionary, from the db

        NOTE: only 1 of blockheight or blockheaderhash can be provided as argument,
            but not both, or else ValueError will be thrown

        Args:
            peer_id: int, peer id that this blockheader is associated with
            blockheight: int, blockheight
            blockheaderhash: str, blockheaderhash
        Returns:
            dict, blockheader index db data, or
            None, if not found
        """

        if blockheight is not None and blockheaderhash is not None:
            raise ValueError(
                "both blockheight and blockheaderhash should not be specified"
            )
        elif blockheight is None and blockheaderhash is None:
            raise ValueError("blockheight or blockheaderhash must be provided")
        elif blockheight is not None:
            cursor = self._conn.cursor()
            res = cursor.execute(
                f"SELECT * FROM blockheader WHERE blockheight='{blockheight}' AND peer_id='{peer_id}';"
            )
        else:
            # blockheaderhash is not None
            cursor = self._conn.cursor()
            res = cursor.execute(
                f"SELECT * FROM blockheader WHERE blockheaderhash='{blockheaderhash}' AND peer_id='{peer_id}';"
            )

        result = res.fetchone()
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
                "peer_id": int(result[10]),
            }
            if result
            else None
        )

    def save_addr(
        self,
        addr: dict,
        peer_id: Optional[int] = None,
        cursor: Optional[sqlite3.Cursor] = None,
    ):
        time_ = addr["time"]
        host = addr["host"]
        port = addr["port"]
        services = addr["services"]

        cols = (
            "(host, port, time, services, peer_id)"
            if peer_id is not None
            else "(host, port, time, services)"
        )
        vals = (
            f"('{host}', {port}, {time_}, {services}, {peer_id})"
            if peer_id is not None
            else f"('{host}', {port}, {time_}, {services})"
        )
        sql_ = f"INSERT INTO addr {cols} VALUES {vals};"
        if cursor is None:
            cursor = self._conn.cursor()
        cursor.execute(sql_)
        self._conn.commit()
        return

    def get_peer_addrs(
        self, peer_id: Union[int | None], limit: Optional[int] = None
    ) -> List:
        if peer_id is None:
            sql_ = f"SELECT host, port, time, services FROM addr WHERE peer_id is NULL;"
        else:
            sql_ = f"SELECT host, port, time, services FROM addr WHERE id={peer_id};"
        if limit is not None:
            sql_ = sql_[:-1]  # remove semicolon
            sql_ += f" LIMIT {limit};"
        cursor = self._conn.cursor()
        res = cursor.execute(sql_)
        results = res.fetchall()
        cursor.close()
        return [
            {
                "host": result[0],
                "port": result[1],
                "time": result[2],
                "services": result[3],
            }
            for result in results
        ]

    def save_peer_addrs(self, peer_id: int, addrs: List[dict]):
        existing_addrs = self.get_peer_addrs(peer_id)
        updated_addrs = existing_addrs + addrs
        cursor = self._conn.cursor()
        cursor.execute(
            f"""
            UPDATE peer SET addrs='{json.dumps(updated_addrs)}' WHERE id={peer_id};
        """
        )
        self._conn.commit()
        cursor.close()

    def add_tx(
        self,
        txid: str,
        blockheaderhash: str,
        n: int,
        revert_block_id: int,
    ):
        """
        Create a new tx row in index db
        Args:
            txid: str, transaction id
            blockheaderhash: str, block header hash for the block this tx is in
            n: int, tx index in block
            revert_block_id: int, block id this tx is added in (for the revert table)
        """
        cursor = self._conn.cursor()
        cursor.execute("BEGIN TRANSACTION;")
        cursor.execute(
            f"INSERT INTO tx (txid, blockheaderhash, n) VALUES ('{txid}', '{blockheaderhash}', {n});"
        )
        cursor.execute(
            f"INSERT INTO revert (revert, txid, vout, block_id) VALUES (1, '{txid}', NULL, {revert_block_id});"
        )
        self._conn.commit()
        cursor.close()

    def remove_tx(self, txid: str):
        """
        Remove tx from tx table
        Args:
            txid: str, transaction id (big endian)
        """
        cursor = self._conn.cursor()
        cursor.execute(f"DELETE FROM tx WHERE txid='{txid}'")
        self._conn.commit()

    def get_tx(self, txid: str) -> Union[dict, None]:
        cursor = self._conn.cursor()
        res = cursor.execute(
            f"SELECT txid, blockheaderhash, n FROM tx WHERE txid='{txid}';"
        )
        result = res.fetchone()
        cursor.close()
        if not result:
            return
        return {
            "txid": result[0],
            "blockheaderhash": result[1],
            "n": result[2],
        }

    def delete_block(self, blockheaderhash: str):
        cursor = self._conn.cursor()
        cursor.execute(f"DELETE FROM block WHERE blockheaderhash='{blockheaderhash}';")
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
        cursor = self._conn.cursor()
        cursor.execute(cmd)
        self._conn.commit()
        cursor.close()

    def get_blockchain_height(self) -> Union[int | None]:
        """
        Get blockchain height according to block index
        Returns:
            blockheight: int, or None if no block row found from query
        """
        cursor = self._conn.cursor()
        res = cursor.execute(
            "SELECT blockheight FROM block ORDER BY blockheight DESC LIMIT 1;"
        )
        result = res.fetchone()
        cursor.close()
        return result[0] if result else None

    def count_blocks(self) -> int:
        cursor = self._conn.cursor()
        res = cursor.execute("SELECT COUNT(*) FROM block;").fetchone()[0]
        cursor.close()
        return int(res)

    def get_block(
        self,
        blockheight: Optional[int] = None,
        blockheaderhash: Optional[str] = None,
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

    def remove_from_utxoset(
        self,
        txid: str,
        vout: int,
        revert_block_id: Optional[int] = None,
        index_ordinals: bool = False,
    ) -> Tuple[Tuple[int, int]]:
        """
        Remove row from utxoset, optionally writing to revert table
        Args:
            revert_block_id: Optional[int], block id this operation corresponds to for revert purposes
        Return:
            ordinal ranges removed e.g. ((0, 16), (420, 690), ...)
        """
        cursor = self._conn.cursor()
        cursor.execute("BEGIN TRANSACTION;")
        utxoset_id = cursor.execute(
            "SELECT id FROM utxoset WHERE txid=? AND vout=?;", (txid, vout)
        ).fetchone()[0]
        if index_ordinals:
            ordinal_ranges = cursor.execute(
                "SELECT start, end FROM ordinal_range WHERE utxoset_id=?;",
                (utxoset_id,),
            ).fetchall()
            revert_block_id = "NULL" if revert_block_id is None else revert_block_id
            cursor.execute(
                "UPDATE ordinal_range SET utxoset_id=NULL, revert_block_id=? WHERE utxoset_id=?;",
                (revert_block_id, utxoset_id),
            )
        cursor.execute("DELETE FROM utxoset WHERE txid=? AND vout=?;", (txid, vout))
        if revert_block_id is not None:
            cursor.execute(
                "INSERT INTO revert (revert, txid, vout, block_id) VALUES (?, ?, ?, ?);",
                (0, txid, vout, revert_block_id),
            )
        self._conn.commit()
        cursor.close()
        return ordinal_ranges if index_ordinals else []

    def add_to_utxoset(
        self,
        txid: str,
        vout: int,
        revert_block_id: int,
        ordinal_ranges: List[List[int]],
        index_ordinals: bool = False,
    ):
        """
        Add to utxo set
        Args:
            txid: str, transaction id
            vout: str, output number
            revert_block_id: int, block id primary key that a potential reversion is for
            ordinal_ranges: list, list of ordinal ranges contained in this utxo
        """
        cursor = self._conn.cursor()
        cursor.execute("BEGIN TRANSACTION;")
        cursor.execute("INSERT INTO utxoset (txid, vout) VALUES (?, ?);", (txid, vout))
        utxoset_id = cursor.execute(
            "SELECT id FROM utxoset WHERE txid=? AND vout=?;", (txid, vout)
        ).fetchone()[0]
        if index_ordinals:
            cursor.executemany(
                "INSERT INTO ordinal_range(start, end, utxoset_id, revert_block_id) VALUES (?, ?, ?, ?);",
                [
                    (start, end, utxoset_id, revert_block_id)
                    for start, end in ordinal_ranges
                ],
            )
        cursor.execute(
            "INSERT INTO revert (revert, txid, vout, block_id) VALUES (?, ?, ?, ?);",
            (1, txid, vout, revert_block_id),
        )
        self._conn.commit()
        cursor.close()

    def find_blockheaderhash_for_utxo(self, txid: str) -> Union[str, None]:
        cursor = self._conn.cursor()
        res = cursor.execute(f"SELECT blockheaderhash FROM tx WHERE txid='{txid}';")
        result = res.fetchone()
        cursor.close()
        return result[0] if result else None

    def get_peer(self, host: str, port: int) -> Union[int, None]:
        cursor = self._conn.cursor()
        result = cursor.execute(
            f"SELECT id FROM peer WHERE host='{host}' AND port={port};"
        ).fetchone()
        cursor.close()
        return result[0] if result else None

    def get_peers(self, is_connected: Optional[bool] = None) -> List[dict]:
        cursor = self._conn.cursor()
        if is_connected is None:
            res = cursor.execute("SELECT * FROM peer;")
        else:
            res = cursor.execute(
                f"SELECT * FROM peer WHERE is_connected={1 if is_connected else 0};"
            )
        results = res.fetchall()
        cursor.close()
        return [
            {
                "id": result[0],
                "host": result[1],
                "port": result[2],
                "data": json.loads(result[3]),
                "addrs": json.loads(result[4]) if result[4] else None,
                "invs": result[5],
                "protocol_version": result[6],
                "services": result[7],
                "user_agent": result[8],
                "start_height": result[9],
                "feefilter_feerate": result[10],
                "sendcmpct_announce": result[11],
                "sendcmpct_version": result[12],
            }
            for result in results
        ]

    def remove_peer(self, peer_id: int):
        cursor = self._conn.cursor()
        cursor.execute("BEGIN TRANSACTION;")
        cursor.execute(f"DELETE FROM blockheader WHERE peer_id={peer_id};")
        cursor.execute(f"DELETE FROM peer WHERE id={peer_id};")
        self._conn.commit()
        cursor.close()

    def save_peer(self, host: str, port: int) -> int:
        cursor = self._conn.cursor()
        cursor.execute(f"INSERT INTO peer (host, port) VALUES ('{host}', {port});")
        self._conn.commit()
        res = cursor.execute(
            f"SELECT id FROM peer WHERE host='{host}' and port='{port}';"
        )
        peer_id = res.fetchone()[0]
        cursor.close()
        return peer_id

    def save_peer_data(self, peer_id: int, data: dict):
        cursor = self._conn.cursor()
        res = cursor.execute(f"SELECT data from peer WHERE id='{peer_id}';")
        peer_data = res.fetchone()[0]
        peer_data = json.loads(peer_data) if peer_data else {}
        peer_data.update(data)
        peer_data = json.dumps(peer_data)
        cursor.execute(f"UPDATE peer SET data='{peer_data}' WHERE id='{peer_id}';")
        self._conn.commit()
        cursor.close()

    def get_peer_data(
        self, peer_id: int, key: Optional[str] = None
    ) -> Union[None, str, list, dict, int, float]:
        cursor = self._conn.cursor()
        res = cursor.execute(f"SELECT data FROM peer WHERE id='{peer_id}';")
        result = res.fetchone()
        cursor.close()
        if result:
            data = json.loads(result[0]) if result[0] else {}
        else:
            data = None
        if key and result:
            return data.get(key)
        return data

    def get_block_revert(self, block_id: int):
        """
        Get the revert table entries for a block
        Args:
            block_id: int, block id primary key
        Returns:
            Entries in revert table for block_id, in descending order
        """
        cursor = self._conn.cursor()
        rows = cursor.execute(
            f"SELECT * FROM revert WHERE block_id={block_id} ORDER BY id DESC;"
        ).fetchall()
        cursor.close()
        return [
            {
                "id": row[0],
                "revert": row[1],
                "txid": row[2],
                "vout": row[3],
                "ordinal_ranges": json.loads(row[4]) if row[4] else None,
                "block_id": row[5],
            }
            for row in rows
        ]
