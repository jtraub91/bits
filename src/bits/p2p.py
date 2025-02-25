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
import os
import sqlite3
import time
import traceback
from asyncio import StreamReader, StreamWriter
from collections import deque
from ipaddress import ip_address
from threading import Event, Thread
from typing import List, Optional, Tuple, Union

import bits.blockchain
import bits.crypto
from bits.blockchain import Block, Blockheader, Bytes, genesis_block


BITS_USER_AGENT = f"/bits:{bits.__version__}/"

# default ports
MAINNET_PORT = 8333
TESTNET_PORT = 18333
REGTEST_PORT = 18444

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
    count = payload[0]
    start_index = 1
    if count == 253:
        count = int.from_bytes(payload[1:3], "little")
        start_index = 3
    elif count == 254:
        count = int.from_bytes(payload[1:5], "little")
        start_index = 5
    elif count == 255:
        count = int.from_bytes(payload[1:9], "little")
        start_index = 9
    ret = {"count": count, "inventory": []}
    inventory_len = 36
    for _ in range(count):
        parsed_inventory = parse_inventory(
            payload[start_index : start_index + inventory_len]
        )
        ret["inventory"].append(parsed_inventory)
        start_index += inventory_len
    return ret


parse_notfound_payload = parse_inv_payload


def inventory(type_id: str, hash: str) -> bytes:
    """
    inventory data structure
    https://developer.bitcoin.org/glossary.html#term-Inventory
    """
    return int.to_bytes(
        INVENTORY_TYPE_ID[type_id.upper()], 4, "little"
    ) + bytes.fromhex(hash)


def inv_payload(count: int, inventories: List[inventory]) -> bytes:
    """
    Create inv message payload
    Args:
        count: int, number of inventories
        inventories: List[inventory], list of inventory data structures
    """
    return bits.compact_size_uint(count) + b"".join(inventories)


def parse_inventory(inventory_: bytes) -> dict:
    assert len(inventory_) == 36
    type_id_integer = int.from_bytes(inventory_[:4], "little")
    type_id = list(
        filter(lambda item: item[1] == type_id_integer, INVENTORY_TYPE_ID.items())
    )[0][0]
    return {"type_id": type_id, "hash": inventory_[4:].hex()}


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

        self.index_db_filename = "index.db"
        self.index_db_filepath = os.path.join(self.datadir, self.index_db_filename)
        self.db = Db(self.index_db_filepath)

        self._data = None
        self._addrs = deque([])

        self.inventories = deque([])
        self.blocks = deque([])
        self._header_queue = deque([])
        self.orphan_blocks = {}
        self._pending_getdata_requests = deque([])
        self._pending_getblocks_requests = deque([])
        self._pending_getheaders_request = None

        self.exit_event = Event()

    def __repr__(self):
        return f"peer(id={self._id}, host='{self.host}', port={self.port})"

    def get_data(self, refresh=False):
        if refresh or not self._data:
            self._data = self.db.get_peer_data(self._id)
        return self._data

    async def connect(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        log.info(f"{self} connection opened.")
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
        log.info(f"sending {command} and {len(payload)} payload bytes to {self}...")
        try:
            self.writer.write(msg_ser(self.magic_start_bytes, command, payload))
            await self.writer.drain()
        except ConnectionResetError as err:
            log.error(err)
            log.info(
                f"connection reset while sending {command} to {self}. attempting to re-connect..."
            )
            await self.connect()


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
        max_outgoing_peers: int = 1,
        connection_timeout: int = 5,
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
        fh = logging.FileHandler(os.path.join(self.datadir, "debug.log"), "a")
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
        if not block_dat_files:
            # if there are no dat files yet,

            # write genesis block to disk
            gb = genesis_block(network=self.network)
            self.save_block(gb)

            # update utxoset
            gb_deser = bits.blockchain.block_deser(gb)
            genesis_coinbase_tx = gb_deser["txns"][0]
            self.db.add_to_utxoset(
                gb_deser["blockheaderhash"], genesis_coinbase_tx["txid"], 0
            )
            self.db.add_tx(genesis_coinbase_tx["txid"], gb_deser["blockheaderhash"], 0)
            difficulty = bits.blockchain.difficulty(
                bits.blockchain.target_threshold(
                    bytes.fromhex(gb_deser["nBits"])[::-1]
                ),
                network=self.network,
            )
            blockheight = self.db.get_blockchain_height()
            block_index = self.db.get_block(blockheight)
            self.db.save_node_state(
                network=self.network,
                difficulty=difficulty,
                height=blockheight,
                bestblockheaderhash=block_index["blockheaderhash"],
                time=block_index["nTime"],
                mediantime=block_index["nTime"],
            )

        self.message_queue = deque([])
        self._unhandled_message_queue = deque([])
        self._ibd: bool = False

        self._block_cache: dict[str, dict] = {}
        # block cache e.g.
        # {"<blockheaderhash": {"time": <time:int>, "data": <block:Block>}, ...}
        # upon each entry, record time stamp,
        # and remove oldest entry if greater than MAX_BLOCK_CACHE_SIZE

        self.peers: list[Peer] = []

        self.exit_event = Event()

    ### handlers ###
    async def handle_command(self, peer: Peer, command: bytes, payload: dict):
        handle_fn_name = f"handle_{command.decode('utf8')}_command"
        handle_fn = getattr(self, handle_fn_name, None)
        if handle_fn:
            try:
                await handle_fn(peer, command, payload)  # pylint: disable=not-callable
            except Exception as err:
                log.error(f"Error while handling {command}: {err.args}")
                log.debug(traceback.format_exc())
                log.debug(f"adding (peer, command, payload) to unhandled_message_queue")
                self._unhandled_message_queue.append((peer, command, payload))
                log.debug(
                    f"there are {len(self._unhandled_message_queue)} messages in unhandled_message_queue"
                )
        else:
            log.warning(
                f"no handler {handle_fn_name} for {command}, saving to unhandled_message_queue"
            )
            self._unhandled_message_queue.append((peer, command, payload))
            await asyncio.sleep(0)

    async def handle_feefilter_command(
        self, peer: Peer, command: bytes, payload: bytes
    ):
        payload = parse_feefilter_payload(payload)
        self.db.save_peer_data(peer._id, {"feefilter": payload})
        self.db._curs.execute(
            f"UPDATE peer SET feefilter_feerate={payload['feerate']} WHERE id={peer._id};"
        )
        self.db._conn.commit()

    async def handle_addr_command(self, peer: Peer, command: bytes, payload: bytes):
        payload = parse_addr_payload(payload)
        addrs = payload["addrs"]
        peer._addrs.extend(addrs)
        self.db.save_peer_addrs(peer._id, addrs)
        log.debug(f"{len(addrs)} network addrs to queue for {peer}")

    async def handle_inv_command(self, peer: Peer, command: bytes, payload: bytes):
        parsed_payload = parse_inv_payload(payload)
        count = parsed_payload["count"]
        inventories = parsed_payload["inventory"]
        log.trace(f"handling {count} inventories received from {peer}...")
        if self._ibd:

            non_msg_block_inventories = list(
                filter(lambda inv: inv["type_id"] != "MSG_BLOCK", inventories)
            )
            non_msg_block_typeset = set(
                [inv["type_id"] for inv in non_msg_block_inventories]
            )
            log.trace(
                f"ibd: {len(non_msg_block_inventories)} inventories of type(s) {non_msg_block_typeset} ignored for {peer}"
            )
            inventories = list(
                filter(lambda inv: inv["type_id"] == "MSG_BLOCK", inventories)
            )

        peer_inventories = peer.inventories

        new_inventories = [inv for inv in inventories if inv not in peer_inventories]
        peer.inventories.extend(new_inventories)
        log.info(
            f"{len(new_inventories)} new inventories added for {peer}, total: {len(peer.inventories)}"
        )

    async def handle_headers_command(self, peer: Peer, command: bytes, payload: bytes):
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

        peer._header_queue.extend(blockheaders)
        log.trace(f"{len(peer._header_queue)} blockheaders in queue for {peer}")

    async def handle_block_command(self, peer: Peer, command: bytes, payload: bytes):
        blockhash = bits.crypto.hash256(payload[:80]).hex()
        block = bits.blockchain.block_deser(payload)
        pending_getdata_request = next(
            filter(
                lambda inv: inv["type_id"] == "MSG_BLOCK" and inv["hash"] == blockhash,
                peer._pending_getdata_requests,
            ),
            None,
        )
        pending_getblocks_request = next(
            # criteria for matching pending getblocks request
            filter(
                lambda bh: bh == block["prev_blockheaderhash"],
                peer._pending_getblocks_requests,
            ),
            None,
        )
        peer.blocks.append(payload)
        if pending_getdata_request:
            peer._pending_getdata_requests.remove(pending_getdata_request)
            peer.inventories.remove(pending_getdata_request)
        if pending_getblocks_request:
            peer._pending_getblocks_requests.remove(pending_getblocks_request)

    async def handle_sendcmpct_command(
        self, peer: Peer, command: bytes, payload: bytes
    ):
        payload = parse_sendcmpct_payload(payload)
        self.db.save_peer_data(peer._id, {"sendcmpct": payload})
        self.db._curs.execute(
            f"UPDATE peer SET sendcmpct_announce={payload['announce']}, sendcmpct_version={payload['version']} WHERE id={peer._id};"
        )
        self.db._conn.commit()

    async def handle_getheaders_command(
        self, peer: Peer, command: bytes, payload: bytes
    ):
        payload = parse_getheaders_payload(payload)
        await peer.send_command(b"headers")

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
        """
        if timeout is None:
            timeout = self.connection_timeout
        for peer in peers:
            if len(self.peers) >= self.max_outgoing_peers:
                log.warning(
                    f"connect_peers loop exit. max_outgoing_peers already reached"
                )
                break
            log.trace(f"connecting {peer}...")
            await asyncio.wait_for(peer.connect(), timeout)
            log.info(f"connected to {peer}")
            peer_id = self.db.get_peer(peer.host, peer.port)
            if not peer_id:
                peer_id = self.db.save_peer(peer.host, peer.port)
                # save hardcoded genesis block to blockheader table for peer
                genesis_blockheader = Blockheader(
                    genesis_block(network=self.network)[:80]
                )
                self.db.save_blockheader(
                    0,
                    genesis_blockheader["blockheaderhash"],
                    genesis_blockheader["version"],
                    genesis_blockheader["prev_blockheaderhash"],
                    genesis_blockheader["merkle_root_hash"],
                    genesis_blockheader["nTime"],
                    genesis_blockheader["nBits"],
                    genesis_blockheader["nNonce"],
                    bits.blockchain.new_chainwork("0", genesis_blockheader["nBits"]),
                    peer_id,
                )
                log.info(f"{peer} saved to db.")
            peer._id = peer_id
            try:
                connect_to_peer_task = asyncio.create_task(self.connect_to_peer(peer))
                await asyncio.wait_for(connect_to_peer_task, timeout)
            except Exception as err:
                log.error(
                    f"exception occurred '{err}' while attempting to complete connection handshake for {peer}"
                )
                self.db.remove_peer(peer._id)
                log.info(f"{peer} removed from db")
            else:
                version_data = connect_to_peer_task.result()
                # TODO: verify version data more rigorously?
                # nonce, timestamp, recv / trans addrs services
                log.debug(f"{peer} version payload: {version_data}")
                self.db.save_peer_data(peer._id, {"version": version_data})
                self.db._curs.execute(
                    f"UPDATE peer SET protocol_version={version_data['protocol_version']}, services={version_data['services']}, user_agent='{version_data['user_agent']}', start_height='{version_data['start_height']}' WHERE id={peer._id};"
                )
                self.db._conn.commit()
                log.info(f"version data for {peer} saved to db")
                self.db._curs.execute(
                    f"UPDATE peer SET is_connected=1 WHERE id={peer._id};"
                )
                self.db._conn.commit()
                self.peers.append(peer)
                asyncio.create_task(self.outgoing_peer_recv_loop(peer))
                asyncio.create_task(self.headers_sync(peer))
                asyncio.create_task(peer.send_command(b"getaddr"))
                asyncio.create_task(self.process_addrs(peer))

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
                self.message_queue.append((peer, command, payload))
            await asyncio.sleep(0)
        log.info(f"exiting peer recv loop for {peer}")
        await peer.close()
        log.info(f"{peer} socket is closed.")
        self.db._curs.execute("BEGIN TRANSACTION")
        self.db._curs.execute(f"UPDATE peer SET is_connected=0 WHERE id={peer._id};")
        self.db._curs.execute("COMMIT;")
        self.peers.remove(peer)
        log.info(f"{peer} removed from self.peers.")

    def handle_incoming_peer(self):
        return

    async def incoming_peer_server(self):
        server = await asyncio.start_server(self.handle_incoming_peer, "0.0.0.0", 10101)
        async with server:
            await server.serve_forever()

    async def message_handler_loop(self):
        while not self.exit_event.is_set():
            if self.message_queue:
                peer, command, payload = self.message_queue.popleft()
                asyncio.create_task(self.handle_command(peer, command, payload))
            await asyncio.sleep(0)
        log.info("message handler loop exited.")

    def startup_checks(self):
        # check datadir for internal consistency
        dat_filenames = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        number_of_blocks_on_disk = 0
        for dat_filename in dat_filenames:
            blocks = self.parse_dat_file(os.path.join(self.blocksdir, dat_filename))
            last_block = blocks[-1]
            number_of_blocks_on_disk += len(blocks)
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
            node_state = self.db.get_node_state()
            if node_state["bestblockheaderhash"] != last_block_index["blockheaderhash"]:
                raise AssertionError(
                    f"bestblockheaderhash stored in node_state {node_state['bestblockheaderhash']} is not equal to the last block's header hash {last_block_index['blockheaderhash']}. This probably means that the utxoset update was interrupted during validation."
                )

    def run(self):
        asyncio.run(self.main(), debug=True)

    def start(self):
        self.exit_event.clear()
        self._thread = Thread(target=self.run)
        self._thread.start()

    def stop(self):
        log.info("stopping node gracefully...")
        for peer in self.peers:
            peer.exit_event.set()
            log.info(f"peer {peer._id} exit event set")
        self.exit_event.set()
        log.info("node exit event set")

    async def main(self, reindex=False):
        self.db.save_node_state(running=True)
        if reindex or not os.path.exists(self.index_db_filepath):
            # to rebuild the index do we need to validate each block again?
            # or do we assume if block is on disk then it's valid, and do a fast rebuild
            # of the index+utxoset?
            # i suppose we can't detect tampering without a re-validation
            # so reindex, will ignore that
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

        await self.connect_peers(peer_candidates)
        # connected peers have been appended to self.peers,
        # headers_sync, outgoing_peer_recv_loop tasks created, etc.

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
            asyncio.create_task(self.ibd(sync_node))

        asyncio.create_task(self.message_handler_loop())

        tasks = asyncio.all_tasks()
        tasks.remove(asyncio.current_task())
        await asyncio.gather(*tasks)
        self.db.save_node_state(running=False)

    async def process_addrs(self, peer: Peer):
        """
        Process the addrs peer has received, by attempting to connect
        """
        while not self.exit_event.is_set():
            if peer._addrs:
                addr = peer._addrs.popleft()
                if len(self.peers) < self.max_outgoing_peers:
                    if (addr["host"], addr["port"]) in [
                        (peer_.host, peer_.port) for peer_ in self.peers
                    ]:
                        # don't connect to peers we've already connected to
                        # just save to db
                        self.db.save_addr(addr, peer_id=peer._id)
                        continue
                    potential_peer = Peer(
                        addr["host"], addr["port"], self.network, self.datadir
                    )

                    try:
                        await self.connect_peers([potential_peer])
                    except (
                        asyncio.TimeoutError,
                        ConnectionRefusedError,
                        OSError,
                    ) as err:
                        log.debug(f"failed to connect to {potential_peer} - {err}")
                        self.db.save_addr(addr, peer_id=peer._id)
                    else:
                        log.info(
                            f"connected to {potential_peer}. total outgoing connected peers: {len(self.peers)}"
                        )
                        self.db.save_addr(addr, peer_id=peer._id)
                        addr["time"] = int(time.time())
                        self.db.save_addr(addr)
                else:
                    # if we're already at max outgoing peers, just save to db
                    self.db.save_addr(addr, peer_id=peer._id)
            await asyncio.sleep(0.1)
        log.trace(f"process_addrs loop exit for {peer}")

    async def headers_sync(self, peer: Peer):
        """
        Headers first sync
        """
        peer_version_data = self.db.get_peer_data(peer._id, "version")
        peer_start_height = peer_version_data["start_height"]

        current_blockheaders = self.db.get_blockheaders(peer._id)
        current_blockheader_height = self.db._curs.execute(
            f"SELECT blockheight FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 1;"
        ).fetchone()[0]
        while (
            current_blockheader_height < peer_start_height
            and not self.exit_event.is_set()
        ):

            best_blockheaderhash = self.db._curs.execute(
                f"SELECT blockheaderhash FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 1"
            ).fetchone()[0]
            peer._pending_getheaders_request = best_blockheaderhash
            await peer.send_command(
                b"getheaders",
                getblocks_payload([bytes.fromhex(best_blockheaderhash)[::-1]]),
            )
            while peer._pending_getheaders_request and not self.exit_event.is_set():
                await asyncio.sleep(0)

            self.db._curs.execute("BEGIN TRANSACTION;")
            while peer._header_queue and not self.exit_event.is_set():
                current_blockheader_height = self.db._curs.execute(
                    f"SELECT blockheight FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 1;"
                ).fetchone()[0]
                current_blockheader_dict = self.db.get_blockheader(
                    peer._id, blockheight=current_blockheader_height
                )

                next_blockheader = peer._header_queue.popleft()
                next_blockheader_height = current_blockheader_height + 1

                if not bits.blockchain.check_blockheader(
                    next_blockheader, network=self.network
                ):
                    raise CheckBlockError(
                        f"blockheader {next_blockheader['blockheaderhash']} check failed"
                    )

                if next_blockheader["blockheaderhash"] in current_blockheaders:
                    raise AcceptBlockError(
                        f"next blockheader hash {next_blockheader['blockheaderhash']} already found in current blockheaders"
                    )

                if (
                    next_blockheader["prev_blockheaderhash"]
                    != current_blockheader_dict["blockheaderhash"]
                ):
                    raise AcceptBlockError(
                        f"next blockheader {next_blockheader['blockheaderhash']} prev blockheader hash ({next_blockheader['prev_blockheaderhash']}) does not match current blockheader hash ({current_blockheader_dict['blockheaderhash']})"
                    )

                # check nbits is set correctly
                next_nbits_set = self.get_next_nbits(next_blockheader, peer_id=peer._id)
                if next_blockheader["nBits"] not in next_nbits_set:
                    raise AcceptBlockError(
                        f"next blockheader {next_blockheader['blockheaderhash']} nBits {next_blockheader['nBits']} is not in {next_nbits_set}"
                    )

                _query_results = self.db._curs.execute(
                    f"SELECT nTime FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 11;"
                ).fetchall()
                last_11_times = [result[0] for result in _query_results]
                median_time_ = bits.blockchain.median_time(last_11_times)
                if next_blockheader["nTime"] <= median_time_:
                    raise AcceptBlockError(
                        f"next blockheader {next_blockheader['blockheaderhash']} nTime {next_blockheader['nTime']} is not strictly greater than the median time {median_time_}"
                    )

                current_time = time.time()
                if next_blockheader["nTime"] > current_time + 7200:
                    raise AcceptBlockError(
                        f"next blockheader {next_blockheader['blockheaderhash']} nTime {next_blockheader['nTime']} is more than two hours in the future {current_time + 7200}"
                    )

                new_blockheader_dict = self.db.save_blockheader(
                    next_blockheader_height,
                    next_blockheader["blockheaderhash"],
                    next_blockheader["version"],
                    next_blockheader["prev_blockheaderhash"],
                    next_blockheader["merkle_root_hash"],
                    next_blockheader["nTime"],
                    next_blockheader["nBits"],
                    next_blockheader["nNonce"],
                    bits.blockchain.new_chainwork(
                        current_blockheader_dict["chainwork"], next_blockheader["nBits"]
                    ),
                    peer._id,
                    commit=False,
                )
                # current_blockheader is updated so that we have it in memory, without having to retrieve them again from sqlite
                current_blockheaders[
                    next_blockheader["blockheaderhash"]
                ] = new_blockheader_dict
                log.info(
                    f"added blockheader {next_blockheader_height} to header chain for {peer}"
                )
                await asyncio.sleep(0)
            self.db._curs.execute("COMMIT;")
            current_blockheader_height = self.db._curs.execute(
                f"SELECT blockheight FROM blockheader WHERE peer_id='{peer._id}' ORDER BY blockheight DESC LIMIT 1;"
            ).fetchone()[0]
            log.debug(f"current blockheader height: {current_blockheader_height}")
        log.info(f"headers_sync loop exit.")

    async def ibd(self, sync_node: Peer):
        """
        Initial Block Download

        blocks first method, for simplicity
        https://developer.bitcoin.org/devguide/p2p_network.html#blocks-first
        """
        self._ibd = True
        while (
            self.sync_node_start_height > self.db.get_blockchain_height()
            and not self.exit_event.is_set()
        ):
            self.db.save_node_state(
                progress=self.db.get_blockchain_height() / self.sync_node_start_height,
            )
            # get latest blockhash from local blockchain
            blockheight = self.db.get_blockchain_height()
            block_index_data = self.db.get_block(blockheight)

            await sync_node.send_command(
                b"getblocks",
                getblocks_payload(
                    [bytes.fromhex(block_index_data["blockheaderhash"])[::-1]]
                ),
            )
            sync_node._pending_getblocks_requests.append(
                block_index_data["blockheaderhash"]
            )

            # expected inv response is min of 500
            # or difference between sync_node start_height and local blockchain height
            # wait until we have at least that many inventories
            msg_block_inventories = list(
                filter(lambda inv: inv["type_id"] == "MSG_BLOCK", sync_node.inventories)
            )
            while (
                len(msg_block_inventories)
                < min(500, self.sync_node_start_height - blockheight)
                and not self.exit_event.is_set()
            ):
                log.trace("waiting for inventories...")
                await asyncio.sleep(0.1)
                msg_block_inventories = list(
                    filter(
                        lambda inv: inv["type_id"] == "MSG_BLOCK", sync_node.inventories
                    )
                )

            while msg_block_inventories and not self.exit_event.is_set():
                # while we have msg block inventories
                # form getdata message in max 128 inventory chunks
                if len(msg_block_inventories) > 128:
                    msg_block_inventories = msg_block_inventories[:128]
                inventory_list = [
                    inventory(inv["type_id"], inv["hash"])
                    for inv in msg_block_inventories
                ]
                log.trace(
                    f"requesting {len(inventory_list)} inventory blocks via getdata..."
                )
                # add to pending getdata requests, remove from inventories
                sync_node._pending_getdata_requests.extend(msg_block_inventories)
                await sync_node.send_command(
                    b"getdata", inv_payload(len(inventory_list), inventory_list)
                )

                getdata_request_start = time.time()
                while (
                    sync_node._pending_getdata_requests and not self.exit_event.is_set()
                ):
                    log.trace(
                        f"sync node has {len(sync_node._pending_getdata_requests)} unfulfilled getdata requests..."
                    )
                    getdata_request_end = time.time()
                    if getdata_request_end - getdata_request_start > 60:
                        log.warning(
                            f"getdata request timeout exceeded. unfulfilled requests: {sync_node._pending_getdata_requests}"
                        )
                        sync_node._pending_getdata_requests = deque([])
                    # wait until all pending getdata requests are fulfilled
                    # pending getdata requests get removed in handle_block_command()
                    await asyncio.sleep(1)

                while sync_node.blocks and not self.exit_event.is_set():
                    # while we have blocks, process them
                    block = sync_node.blocks.popleft()
                    blockhash = bits.crypto.hash256(block[:80])
                    try:
                        self.accept_block(block)
                    except PossibleOrphanError as err:
                        # sync_node.orphan_blocks.update({blockhash: block})
                        # log.warning(
                        #     f"possible orphan block added to pool (size= {len(sync_node.orphan_blocks)} blocks, {sum([len(b) for b in sync_node.orphan_blocks.values()])} bytes)"
                        # )
                        blockhash = blockhash[::-1].hex()
                        log.debug(
                            f"possible orphan block received during IBD. discarding {blockhash} ..."
                        )
                    except PossibleForkError as err:
                        log.error(err)
                        log.warning(f"block {blockhash} is part of a potential fork")
                        best_peer = self.get_best_peer()
                        log.info(
                            f"switching from {sync_node} to {best_peer} as sync_node..."
                        )
                        # TODO: rollback to common ancestor, if necessary
                        sync_node = best_peer
                    except (CheckBlockError, AcceptBlockError) as err:
                        log.error(err)
                        raise err
                    except ConnectBlockError as err:
                        log.error(err)
                        self.db._curs.execute("ROLLBACK;")
                        log.info(
                            f"changes to utxoset / node_state in {self.index_db_filename} rolled back"
                        )
                        # rollback block & block index
                        _deleted_block = self.rollback_block()
                        log.trace(_deleted_block)
                        raise err

                    await asyncio.sleep(0)

                msg_block_inventories = list(
                    filter(
                        lambda inv: inv["type_id"] == "MSG_BLOCK", sync_node.inventories
                    )
                )
                await asyncio.sleep(0)
            await asyncio.sleep(0)
        self._ibd = False
        self.db.save_node_state(ibd=self._ibd)

    def rollback_block(self) -> bytes:
        """
        Delete block chain tip from disk and index db

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
        return deleted_block_data

    def save_block(self, block: bytes):
        """
        Add block to local blockhain, i.e. save to disk, write to db index

        observe max_blockfile_size &
        number files blk00000.dat, blk00001.dat, ...

        Args:
            blocks: List[bytes]
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
            filename = f"blk{new_blk_no.zfill(5)}.dat"
            filepath = os.path.join(self.blocksdir, filename)
            dat_file = open(filepath, "wb")
            start_offset = 0
            dat_file.write(block_data)
        dat_file.close()
        log.info(f"block {blockheight} saved to {filename}")

        # save hash / header to db index
        self.db.save_block(
            blockheight,
            blockheader_data["blockheaderhash"],
            blockheader_data["version"],
            blockheader_data["prev_blockheaderhash"],
            blockheader_data["merkle_root_hash"],
            blockheader_data["nTime"],
            blockheader_data["nBits"],
            blockheader_data["nNonce"],
            rel_path,
            start_offset,
        )
        log.info(f"block {blockheight} saved to {self.index_db_filename}")

    def get_blockchain_info(self) -> Union[dict, None]:
        node_state = self.db.get_node_state()
        node_state.pop("ibd")
        node_state.pop("running")
        return node_state

    def get_node_info(self) -> Union[dict, None]:
        node_state = self.db.get_node_state()
        peers = self.db.get_peers(is_connected=True)
        # pop off peer addrs info
        for peer in peers:
            addrs = peer.pop("addrs")
            invs = peer.pop("invs")
            data = peer.pop("data")
            peer["addrs"] = len(addrs) if addrs else 0
            num_blockheaders = self.db._curs.execute(
                f"SELECT COUNT(*) FROM blockheader WHERE peer_id={peer['id']};"
            ).fetchone()[0]
            peer["blockheaders"] = num_blockheaders
            best_blockheader = self.db.get_blockheader(
                peer["id"], blockheight=num_blockheaders - 1
            )
            peer["bestblockheaderhash"] = best_blockheader["blockheaderhash"]
            peer["bestblockheight"] = best_blockheader["blockheight"]
            peer["totalchainwork"] = best_blockheader["chainwork"]
        return {"running": node_state.pop("running"), "peers": peers}

    def rebuild_index(self):
        raise NotImplementedError
        # TODO: need to account for utxoset rebuild
        log.info("rebuilding index...")
        dat_filenames = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        log.info(f"found {len(dat_filenames)} in {self.blocksdir}")
        blockheight = 0
        for i, filename in enumerate(dat_filenames, start=1):
            log.info(f"parsing {filename} (file {i} of {len(dat_filenames)})... ")
            with open(os.path.join(self.blocksdir, filename), "rb") as dat_file:
                start_offset = dat_file.tell()
                magic = dat_file.read(4)
                while magic:
                    assert magic == self.magic_start_bytes, "magic mismatch"
                    length = int.from_bytes(dat_file.read(4), "little")
                    block = dat_file.read(length)
                    assert len(block) == length, "length mismatch"
                    block_dict = bits.blockchain.block_deser(block)
                    self.db.save_block(
                        blockheight,
                        block_dict["blockheaderhash"],
                        block_dict["version"],
                        block_dict["prev_blockheaderhash"],
                        block_dict["merkle_root_hash"],
                        block_dict["nTime"],
                        block_dict["nBits"],
                        block_dict["nNonce"],
                        filename,
                        start_offset,
                    )
                    log.info(f"block {blockheight} saved to {self.index_db_filename}")
                    blockheight += 1

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

    def accept_block(self, block: Union[Block, Bytes, bytes]) -> bool:
        """
        Validate block as new tip
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

        # if prev blockhash field DOES match blockchain tip,
        # the next couple rules (nbits & timestamp checks)
        # must pass for the block to be considered valid

        # check nBits correctly sets difficulty
        if proposed_block["nBits"] not in self.get_next_nbits(proposed_block):
            raise AcceptBlockError(
                f"proposed block nBits {proposed_block['nBits']} is not in {self.get_next_nbits(proposed_block)}"
            )

        # ensure timestamp is strictly greater than the median_time of last 11 blocks
        last_11_block_index_ = [
            self.db.get_block(current_blockheight - i)
            for i in range(min(current_blockheight + 1, 11))
        ]
        last_11_times = [block["nTime"] for block in last_11_block_index_]
        median_time = bits.blockchain.median_time(last_11_times)
        if proposed_block["nTime"] <= median_time:
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

        # check if proposed block is in the most work chain,
        best_peer = self.get_best_peer()
        res = self.db._curs.execute(
            f"SELECT blockheaderhash FROM blockheader WHERE peer_id={best_peer._id} AND blockheight={proposed_blockheight} AND blockheaderhash='{proposed_block['blockheaderhash']}';"
        ).fetchone()
        if not res:
            raise PossibleForkError(
                f"proposed block {proposed_block['blockheaderhash']} is not in the most work chain"
            )

        ### save block to disk and index db ###
        self.save_block(block)

        # cleanup proposed block variables
        del proposed_blockheight
        del proposed_block

        # full transaction validation of now latest block

        # begin transaction
        self.db._curs.execute("BEGIN TRANSACTION;")
        # now we update utxoset step-by-step during tx validation,
        # and ROLLBACK upon error, if necessary

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
        self.db.add_tx(coinbase_tx["txid"], current_block["blockheaderhash"], 0)

        coinbase_tx_txouts = coinbase_tx["txouts"]
        coinbase_tx_txouts_total_value = 0
        for txo in coinbase_tx_txouts:
            coinbase_tx_txouts_total_value += txo["value"]

        # update utxoset with coinbase tx outputs
        for vout in range(len(coinbase_tx_txouts)):
            self.db.add_to_utxoset(
                current_block["blockheaderhash"],
                coinbase_tx["txid"],
                vout,
                commit=False,
            )

        MIN_TX_FEE = 0

        # tally up the surplus value aka miner fees, block fees,
        # ... "tips" seems like an apt name
        miner_tips = 0
        for txn_i, txn in enumerate(current_block["txns"][1:], start=1):
            self.db.add_tx(txn["txid"], current_block["blockheaderhash"], txn_i)

            log.trace(
                f"validating tx {txn_i} of {len(current_block['txns'][1:])} non-coinbase txns in new block {current_blockheight}..."
            )
            txn_txid = txn["txid"]

            txn_value_in = 0
            txn_value_out = 0
            for txin_i, tx_in in enumerate(txn["txins"]):
                txin_txid = tx_in["txid"]
                txin_vout = tx_in["vout"]

                # check for double spending by checking that the transaction exists
                # in the current utxo set
                utxo_blockheaderhash = self.db.find_blockheaderhash_for_utxo(
                    txin_txid, txin_vout
                )
                if not utxo_blockheaderhash:
                    raise ConnectBlockError(
                        f"a matching blockheaderhash for txo {txin_vout} in txid {txin_txid} was not found in the utxoset"
                    )
                block_utxos = self.db.get_block_utxos(utxo_blockheaderhash)
                if {"txid": txin_txid, "vout": txin_vout} not in block_utxos:
                    raise ConnectBlockError(
                        f"utxo not found in utxoset for blockheaderhash {utxo_blockheaderhash}"
                    )

                # get the utxo transaction in full
                log.trace(f"retrieving utxo(txid={txin_txid}, vout={txin_vout})...")
                utxo_block_index_data = self.db.get_block(
                    blockheaderhash=utxo_blockheaderhash
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
                    f"evaluating script for tx input {txin_i} in txn {txn_i} of new block {current_blockheight}..."
                )
                if not bits.script.eval_script(
                    script_, bytes.fromhex(utxo_tx["raw"]), txin_vout
                ):
                    raise ConnectBlockError(
                        f"script evaluation failed for txin {txin_i} in txn {txn_i} in block(blockheaderhash={current_block['blockheaderhash']})"
                    )
                log.trace(
                    f"script for tx input {txin_i} in txn {txn_i} of new block {current_blockheight} succeeded."
                )

                # this tx_in succeeds, update utxoset
                log.trace(
                    f"removing tx input {txin_i} in txn {txn_i} of new block {current_blockheight} from utxoset... "
                )
                self.db.remove_from_utxoset(
                    utxo_block["blockheaderhash"], txin_txid, txin_vout, commit=False
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
            for vout in range(len(txn["txouts"])):
                self.db.add_to_utxoset(
                    current_block["blockheaderhash"], txn["txid"], vout, commit=False
                )

        max_block_reward = (
            bits.blockchain.block_reward(current_blockheight) + miner_tips
        )
        if coinbase_tx_txouts_total_value > max_block_reward:
            raise ConnectBlockError(
                f"block {current_block['blockheaderhash']} coinbase tx spends more than the max block reward"
            )
        log.debug(
            f"validated all of {len(current_block['txns'])} txns in block {current_blockheight}."
        )
        last_11_block_index_ = [
            self.db.get_block(current_blockheight - i)
            for i in range(min(current_blockheight + 1, 11))
        ]
        last_11_times = [block["nTime"] for block in last_11_block_index_]
        self.db.save_node_state(
            progress=current_blockheight / self.sync_node_start_height,
            difficulty=bits.blockchain.difficulty(
                bits.blockchain.target_threshold(
                    bytes.fromhex(current_block["nBits"])[::-1]
                )
            ),
            height=current_blockheight,
            bestblockheaderhash=current_block["blockheaderhash"],
            time=current_block["nTime"],
            mediantime=bits.blockchain.median_time(last_11_times),
            commit=False,
        )
        self.db._curs.execute(
            "COMMIT;"
        )  # commit changes to utxoset / node_state to index db
        return True

    def get_best_peer(self) -> Union[Peer, None]:
        chainworks = self.db._curs.execute(
            "SELECT MAX(blockheight), chainwork, peer_id FROM blockheader GROUP BY peer_id;"
        ).fetchall()
        sorted_chainworks = sorted(chainworks, key=lambda cw: int(cw[1], 16))
        best_peer_id = sorted_chainworks[-1][2]
        # possible for multiple peers to have best if they are synced, but we dpn't care
        best_peer = filter(lambda p: p._id == best_peer_id, self.peers)
        return next(best_peer, None)

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

            current_blockheight = self.db._curs.execute(
                f"SELECT blockheight FROM blockheader WHERE peer_id='{peer_id}' ORDER BY blockheight DESC LIMIT 1;"
            ).fetchone()[0]
            current_block_index_data = self.db.get_blockheader(
                peer_id, blockheight=current_blockheight
            )
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
                    last_non_max_nbits_query = self.db._curs.execute(
                        f"SELECT nBits FROM block WHERE nBits!='1d00ffff' AND blockheight>={current_blockheight - (current_blockheight % 2016)} AND blockheight<={current_blockheight} ORDER BY blockheight DESC;"
                    ).fetchone()
                elif isinstance(next_block, Blockheader):
                    last_non_max_nbits_query = self.db._curs.execute(
                        f"SELECT nBits FROM blockheader WHERE nBits!='1d00ffff' AND blockheight>={current_blockheight - (current_blockheight % 2016)} AND blockheight<={current_blockheight} AND peer_id={peer_id} ORDER BY blockheight DESC;"
                    ).fetchone()
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
            log.debug(current_block_index_data)
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
                blockheaderhash TEXT UNIQUE,
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
        self._conn.commit()
        self._curs.execute(
            "CREATE INDEX blockheader_blockheaderhash_index ON blockheader(blockheaderhash, peer_id);"
        )
        self._conn.commit()
        self._curs.execute(
            "CREATE INDEX blockheader_blockheight_index ON blockheader(blockheight, peer_id);"
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
                mediantime INTEGER,

                best_blockheader_chain INTEGER,
                FOREIGN KEY(best_blockheader_chain) REFERENCES blockheader(peer_id)
            );
        """
        )
        self._conn.commit()
        self._curs.execute(
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
        self._conn.commit()
        self._curs.execute("CREATE INDEX tx_txid_index ON tx(txid);")
        self._conn.commit()
        self._curs.execute(
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
        commit: bool = True,
    ) -> dict:
        self._curs.execute(
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
        if commit:
            self._conn.commit()
        new_blockheader_dict = self.get_blockheader(peer_id, blockheight=blockheight)
        return new_blockheader_dict

    def get_blockheaders(self, peer_id: int) -> dict[str, dict]:
        """
        Get blockheaders for a peer from db
        Returns:
            dict, map of blockheaderhash key to blockheader data, ordered by blockheight, ascending
                {
                    <blockheaderhash: str>: <blockheader: dict>,
                    ...
                }
        """
        res = self._curs.execute(
            f"SELECT * FROM blockheader WHERE peer_id='{peer_id}' ORDER BY blockheight ASC;"
        )
        results = res.fetchall()
        return {
            result[2]: {
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
            for result in results
        }

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
            res = self._curs.execute(
                f"SELECT * FROM blockheader WHERE blockheight='{blockheight}' AND peer_id='{peer_id}';"
            )
        else:
            # blockheaderhash is not None
            res = self._curs.execute(
                f"SELECT * FROM blockheader WHERE blockheaderhash='{blockheaderhash}' AND peer_id='{peer_id}';"
            )

        result = res.fetchone()
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

    def save_addr(self, addr: dict, peer_id: Optional[int] = None):
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
        self._curs.execute(sql_)
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
        res = self._curs.execute(sql_)
        results = res.fetchall()
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
        self._curs.execute(
            f"""
            UPDATE peer SET addrs='{json.dumps(updated_addrs)}' WHERE id={peer_id};
        """
        )
        self._conn.commit()

    def add_tx(self, txid: str, blockheaderhash: str, n: int):
        """
        Create a new tx row in index db
        Args:
            txid: str, transaction id
            blockheaderhash: str, block header hash for the block this tx is in
            n: int, tx index in block
        """
        self._curs.execute(
            f"INSERT INTO tx (txid, blockheaderhash, n) VALUES ('{txid}', '{blockheaderhash}', {n});"
        )
        self._conn.commit()

    def get_tx(self, txid: str) -> Union[dict, None]:
        res = self._curs.execute(
            f"SELECT txid, blockheaderhash, n FROM tx WHERE txid='{txid}';"
        )
        result = res.fetchone()
        if not result:
            return
        return {
            "txid": result[0],
            "blockheaderhash": result[1],
            "n": result[2],
        }

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
            res = self._curs.execute(
                f"SELECT * FROM block WHERE blockheight='{blockheight}';"
            )
        else:
            # blockheaderhash is not None
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

    def get_peer(self, host: str, port: int) -> Union[int, None]:
        res = self._curs.execute(
            f"SELECT id FROM peer WHERE host='{host}' AND port={port};"
        )
        result = res.fetchone()
        return result[0] if result else None

    def get_peers(self, is_connected: Optional[bool] = None) -> List[dict]:
        if is_connected is None:
            res = self._curs.execute("SELECT * FROM peer;")
        else:
            res = self._curs.execute(
                f"SELECT * FROM peer WHERE is_connected={1 if is_connected else 0};"
            )
        results = res.fetchall()
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
        self._curs.execute(f"DELETE FROM peer WHERE id={peer_id};")
        self._conn.commit()

    def save_peer(self, host: str, port: int) -> int:
        self._curs.execute(f"INSERT INTO peer (host, port) VALUES ('{host}', {port});")
        self._conn.commit()
        res = self._curs.execute(
            f"SELECT id FROM peer WHERE host='{host}' and port='{port}';"
        )
        peer_id = res.fetchone()[0]
        return peer_id

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
        res = self._curs.execute("SELECT * from node_state;")
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
        res = self._curs.execute("SELECT * from node_state;")
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
