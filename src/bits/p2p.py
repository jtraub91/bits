"""
P2P and stuff

https://developer.bitcoin.org/devguide/p2p_network.html
https://developer.bitcoin.org/reference/p2p_networking.html
https://en.bitcoin.it/wiki/Network
https://en.bitcoin.it/wiki/Protocol_documentation
"""
import asyncio
import base64
import binascii
import json
import logging
import os
import shutil
import socket
import sqlite3
import time
import traceback
from asyncio import StreamReader
from asyncio import StreamWriter
from collections import deque
from threading import Event
from threading import Thread
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import bits.crypto
import bits.db
from bits.blockchain import Block
from bits.blockchain import genesis_block


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


class ConnectBlockError(Exception):
    pass


class AcceptBlockError(Exception):
    pass


class CheckBlockError(Exception):
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
        "ip_addr": parse_ip_addr(payload[12:28]),
        "port": int.from_bytes(payload[28:], "big"),
    }


def parse_ip_addr(ip_addr: bytes) -> str:
    assert len(ip_addr) == 16, "ip_addr must be exactly 16 bytes"

    if ip_addr[:12] == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff":
        # https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses
        ip_addr_str = "::ffff:"
        for i, byte in enumerate(ip_addr[12:]):
            ip_addr_str += str(byte)
            if i != 3:
                # last byte don't append "."
                ip_addr_str += "."
        return ip_addr_str

    ip_addr_str = ""
    for n in range(8):
        nibble = ip_addr[2 * n : 2 * n + 2]
        if nibble != b"\x00\x00":
            ip_addr_str += nibble.hex().upper()
        else:
            if ip_addr_str[-2:] != "::":
                ip_addr_str += ":"
    return ip_addr_str


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

        self._id: int = None

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

        self.inventories = deque([])
        self.blocks = deque([])
        self.orphan_blocks = deque([])
        self._pending_getdata_requests = deque([])
        self._pending_getblocks_requests = deque([])

        self.exit_event = Event()

    def __repr__(self):
        return f"peer(id={self._id},host='{self.host}',port={self.port})"

    async def connect(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        log.info(f"connection opened to peer @ {self.host}:{self.port}")
        self.reader = reader
        self.writer = writer

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
        log.info(f"closed socket connection to peer @ {self.host}:{self.port} ")

    async def recv_msg(self) -> Tuple[bytes, bytes, bytes]:
        """
        Read and deserialize message ( header + payload )
        """
        msg = b""
        while len(msg) != MSG_HEADER_LEN:
            msg += await self.reader.read(MSG_HEADER_LEN - len(msg))

        start_bytes = msg[:4]
        command = msg[4:16].rstrip(b"\x00")
        payload_size = int.from_bytes(msg[16:20], "little")
        checksum = msg[20:24]

        payload = b""
        if payload_size:
            while len(payload) != payload_size:
                payload += await self.reader.read(payload_size - len(payload))

        if checksum != bits.crypto.hash256(payload)[:4]:
            raise ValueError(
                f"checksum failed. {checksum} != {bits.crypto.hash256(payload)[:4]}"
            )
        if start_bytes != self.magic_start_bytes:
            raise ValueError(
                f"magic network bytes mismatch - {start_bytes} not equal to magic start bytes {self.magic_start_bytes}"
            )
        log.info(
            f"read {len(start_bytes + command + payload)} bytes from peer @ {self.host}:{self.port}. command: {command}"
        )
        self._last_recv_msg_time = time.time()

        return start_bytes, command, payload

    async def send_command(self, command: bytes, payload: bytes = b""):
        log.info(
            f"sending {command} and {len(payload)} payload bytes to peer @ {self.host}:{self.port}..."
        )
        self.writer.write(msg_ser(self.magic_start_bytes, command, payload))
        await self.writer.drain()


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
        reindex: bool = False,
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
        self.db = bits.db.Db(self.index_db_filepath)
        if not block_dat_files:
            # if there are no dat files yet,
            # write genesis block
            gb = genesis_block(network=self.network)
            self.save_block(gb)

            # update utxoset
            gb_deser = bits.blockchain.block_deser(gb)
            genesis_coinbase_tx = gb_deser["txns"][0]
            self.db.add_to_utxoset(
                gb_deser["blockheaderhash"], genesis_coinbase_tx["txid"], 0
            )

        else:
            # some block dat files exist,

            # check for indexes,
            # build if non-existent (shouldn't really happen) or reindex=True
            if reindex or not os.path.exists(self.index_db_filepath):
                self.rebuild_index()
            else:
                # check for internally consistency
                # TODO: make more robust
                dat_filenames = sorted(
                    [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
                )
                blocks = []
                for dat_filename in dat_filenames:
                    blocks += self.parse_dat_file(
                        os.path.join(self.blocksdir, dat_filename)
                    )
                number_of_blocks_on_disk = len(blocks)
                number_of_blocks_in_index = self.db.count_blocks()
                assert (
                    number_of_blocks_on_disk == number_of_blocks_in_index
                ), f"number of blocks on disk ({number_of_blocks_on_disk}) does not match number in index ({number_of_blocks_in_index})"

        self.message_queue = deque([])
        self._unhandled_message_queue = deque([])
        self._ibd: bool = False

        self._block_cache: dict[str, dict] = {}
        MAX_BLOCK_CACHE_SIZE = bits.constants.MAX_BLOCKFILE_SIZE
        # block cache e.g.
        # {"<blockheaderhash": {"time": <time:int>, "data": <block:byte>}, ...}
        # upon each entry, record time stamp, and remove oldest entry if greater than MAX_BLOCK_CACHE_SIZE

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

    async def handle_addr_command(self, peer: Peer, command: bytes, payload: bytes):
        payload = parse_addr_payload(payload)
        self.db.save_peer_data(peer._id, {"addr": payload})

    async def handle_inv_command(self, peer: Peer, command: bytes, payload: bytes):
        parsed_payload = parse_inv_payload(payload)
        count = parsed_payload["count"]
        inventories = parsed_payload["inventory"]

        peer_inventories = peer.inventories

        new_inventories = [inv for inv in inventories if inv not in peer_inventories]
        peer.inventories.extend(new_inventories)

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
        if pending_getblocks_request:
            peer._pending_getblocks_requests.remove(pending_getblocks_request)

    async def handle_sendcmpct_command(
        self, peer: Peer, command: bytes, payload: bytes
    ):
        payload = parse_sendcmpct_payload(payload)
        self.db.save_peer_data(peer._id, {"sendcmpct": payload})

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

    async def connect_seeds(self):
        """
        Connect seeds as peers, and schedule outgoing peer recv loop task
        """
        for seed in self.seeds:
            host, port = seed.split(":")
            port = int(port)
            peer = Peer(host, port, self.network, self.datadir)
            await peer.connect()
            peer_id = self.db.save_peer(host, port)
            peer._id = peer_id
            log.info(f"{peer} saved to db.")
            await self.connect_to_peer(peer)
            self.peers.append(peer)

            asyncio.create_task(self.outgoing_peer_recv_loop(peer))

    async def connect_to_peer(self, peer: Peer):
        """
        Connect to peer by performing version / verack handshake
        https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
        """
        log.info(f"sending version message to peer @ {peer.host}:{peer.port}...")

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
        self.db.save_peer_data(peer._id, {"version": parse_payload(command, payload)})
        log.info(f"version data saved to db for {peer}")

        # send verack
        await peer.send_command(b"verack")

        # wait for verack message
        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"verack", f"expected verack command, not {command}"

        log.info(f"connection handshake established for {peer}")

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
            except asyncio.TimeoutError:
                if time.time() - peer._last_recv_msg_time > PEER_INACTIVITY_TIMEOUT:
                    peer.exit_event.set()
            else:
                self.message_queue.append((peer, command, payload))
            await asyncio.sleep(0)
        log.info(f"exiting peer recv loop for peer @ {peer.host}:{peer.port}")
        await peer.close()
        log.info(f"peer @ {peer.host}:{peer.port} socket is closed.")

    async def incoming_peer_server(self):
        raise NotImplementedError()  # yet

    async def message_handler_loop(self):
        while not self.exit_event.is_set():
            if self.message_queue:
                peer, command, payload = self.message_queue.popleft()
                asyncio.create_task(self.handle_command(peer, command, payload))
            await asyncio.sleep(0)

    async def main(self):
        await self.connect_seeds()
        asyncio.create_task(self.main_loop())
        await self.message_handler_loop()

    def run(self):
        asyncio.run(self.main())

    def start(self):
        self.exit_event.clear()
        self._thread = Thread(target=self.run)
        self._thread.start()

    def stop(self):
        for peer in self.peers:
            peer.exit_event.set()
            log.info(f"peer {peer._id} exit event set")
        self.exit_event.set()
        log.info("node exit event set")

    async def main_loop(self):
        for peer in self.peers:
            await peer.send_command(b"getaddr")

        # choose a peer as sync node
        sync_node = self.peers[0]

        # if blockchain is 144 blocks behind peer (~24 hr) enter ibd
        blockheight = self.db.get_blockchain_height()
        sync_node_version_data = self.db.get_peer_data(sync_node._id, "version")
        if sync_node_version_data["start_height"] - blockheight > 144:
            log.info(
                f"local blockchain is behind sync node @ {sync_node.host}:{sync_node.port} by {sync_node_version_data['start_height'] - blockheight} blocks. Entering IBD..."
            )
            await self.ibd(sync_node)
        log.info("exiting IBD...local blockchain is synced with sync node.")

        while not self.exit_event.is_set():
            await asyncio.sleep(1)

    async def ibd(self, sync_node: Peer):
        """
        Initial Block Download

        blocks first method, for simplicity
        https://developer.bitcoin.org/devguide/p2p_network.html#blocks-first
        """
        self._ibd = True
        sync_node_version_data = self.db.get_peer_data(sync_node._id, "version")
        sync_node_start_height = sync_node_version_data["start_height"]
        while sync_node_start_height > self.db.get_blockchain_height():

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
            while len(msg_block_inventories) < min(
                500, sync_node_start_height - blockheight
            ):
                await asyncio.sleep(0.1)
                msg_block_inventories = list(
                    filter(
                        lambda inv: inv["type_id"] == "MSG_BLOCK", sync_node.inventories
                    )
                )

            while msg_block_inventories:
                # while we have msg block inventories
                # form getdata message in max 128 inventory chunks
                if len(msg_block_inventories) > 128:
                    msg_block_inventories = msg_block_inventories[:128]
                inventory_list = [
                    inventory(inv["type_id"], inv["hash"])
                    for inv in msg_block_inventories
                ]
                await sync_node.send_command(
                    b"getdata", inv_payload(len(inventory_list), inventory_list)
                )
                # add to pending getdata requests, remove from inventories
                sync_node._pending_getdata_requests.extend(msg_block_inventories)
                [sync_node.inventories.remove(inv) for inv in msg_block_inventories]

                while sync_node._pending_getdata_requests:
                    # wait until all pending getdata requests are fulfilled
                    # pending getdata requests get removed in handle_block_command()
                    await asyncio.sleep(0.1)

                while sync_node.blocks and not self.exit_event.is_set():
                    # while we have blocks, process them
                    block = sync_node.blocks.popleft()
                    try:
                        # accept_block(block) checks block independently via bits.blockchain.check_block
                        # continues with checks in context as new block, saves block to disk and writes
                        #  to block indexes and utxoset, then continues validation of transactions
                        # if an error is thrown handle as follows
                        self.accept_block(block)
                    except PossibleOrphanError as err:
                        sync_node.orphan_blocks.append(block)
                        log.warning(
                            f"possible orphan block added to pool (size= {len(sync_node.orphan_blocks)} blocks, {sum([len(b) for b in sync_node.orphan_blocks])} bytes)"
                        )
                    except (CheckBlockError, AcceptBlockError) as err:
                        log.error(err)
                        raise err
                    except ConnectBlockError as err:
                        log.error(err)
                        self.db._curs.execute("ROLLBACK;")
                        log.info(
                            f"changes to utxoset in {self.index_db_filename} rolled back"
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

        self._ibd = False

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
        with open(block_index["datafile"], "rb") as dat_file:
            truncated_bytes = dat_file.read(block_index["datafile_offset"])
            magic = dat_file.read(4)
            assert magic == self.magic_start_bytes, "magic mismatch"
            length = int.from_bytes(dat_file.read(4), "little")
            deleted_block_data = dat_file.read(length)
            assert len(deleted_block_data) == length, "length mismatch"
        with open(block_index["datafile"], "wb") as dat_file:
            dat_file.write(truncated_bytes)
        log.info(
            f"block {blockheight} deleted from {os.path.split(block_index['datafile'])[-1]}"
        )
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

        if self.db.get_blockchain_height() is None:
            # genesis block
            blockheight = 0
        else:
            blockheight = self.db.get_blockchain_height() + 1
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
            filepath,
            start_offset,
        )
        log.info(f"block {blockheight} saved to {self.index_db_filename}")

    def get_blockchain_info(self) -> dict:
        return {
            "blockheight": self.db.get_blockchain_height(),
            "network": self.network,
        }

    def rebuild_index(self):
        # TODO: need to account for utxoset rebuild
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

    def accept_block(self, block: bytes) -> bool:
        """
        Validate block as new tip
        Args:
            block: bytes, raw block data
        Returns:
            bool: True if block is accepted
        Throws:
            CheckBlockError: if block fails context indepedent checks
            AcceptBlockError: if block fails context dependent checks
            PossibleOrphanError: if block is potential orphan
            ConnectBlockError: if error is thrown during full tx validation,
                i.e. after block is saved to disk
        """
        if not bits.blockchain.check_block(block, network=self.network):
            raise CheckBlockError("block failed context independent checks")

        current_blockheight = self.db.get_blockchain_height()
        current_block = self.db.get_block(blockheight=current_blockheight)

        proposed_blockheight = current_blockheight + 1
        proposed_block = bits.blockchain.block_deser(block)

        # check for duplicate hash in blockchain index
        if self.db.get_block(blockheaderhash=proposed_block["blockheaderhash"]):
            raise AcceptBlockError(
                f"proposed blockhash {proposed_block['blockheaderhash']} already found in block index db"
            )

        # check prev block hash matches current block hash
        # if not, block is potential orphan
        if proposed_block["prev_blockheaderhash"] != current_block["blockheaderhash"]:
            raise PossibleOrphanError(
                f"proposed block {proposed_block['blockheaderhash']} prev blockheader hash {proposed_block['prev_blockheaderhash']} does not match current blockchain tip's header hash {current_block['blockheaderhash']}"
            )

        # if prev blockhash field DOES match blockchain tip, the next couple rules (nbits & timestamp checks)
        # must pass for the block to be considered valid
        # i.e. if not the block is not a valid orphan (thus AcceptBlockError is thrown)
        # and also these checks don't even make sense if prev_blockheader does not match the tip

        # check nBits correctly sets difficulty
        if proposed_block["nBits"] not in self.get_next_nbits(proposed_block):
            raise AcceptBlockError(
                f"proposed block nBits {proposed_block['nBits']} is not in {self.get_next_nbits(proposed_block)}"
            )

        # ensure timestamp is strictly greater than the median_time of last 11 blocks
        if proposed_block["nTime"] <= self.median_time():
            raise AcceptBlockError(
                f"proposed block nTime {proposed_block['nTime']} is not strictly greater than the median time {self.median_time()}"
            )
        # ensure timestamp is not more than two hours in future
        current_time = time.time()
        if proposed_block["nTime"] > current_time + 7200:
            raise AcceptBlockError(
                f"proposed block nTime {proposed_block['nTime']} is more than two hours in the future {current_time + 7200}"
            )

        # check all transacations are finalized
        for txn in proposed_block["txns"]:
            if not bits.tx.is_final(txn):
                raise AcceptBlockError(
                    f"block {proposed_block['blockheaderhash']} has non-final transaction"
                )

        # save block to disk and index db
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
        current_block = self.db.get_block(blockheight=current_blockheight)
        cached_current_block_data = self._block_cache.get(
            current_block["blockheaderhash"]
        )
        if cached_current_block_data:
            current_block_data = cached_current_block_data["block"]
        else:
            current_block_data = self.get_block_data(
                datafile=current_block["datafile"],
                datafile_offset=current_block["datafile_offset"],
                cache=True,
            )
        current_block_data_dict = current_block_data.dict()

        # TODO check new block is from the most work chain,
        # shouldn't matter for now since we're only syncing from one peer rn

        # get total value spent by coinbase transaction
        coinbase_tx = current_block_data_dict["txns"][0]
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
        for txn_i, txn in enumerate(current_block_data_dict["txns"][1:], start=1):
            log.trace(
                f"validating tx {txn_i} of {len(current_block_data_dict['txns'][1:])} non-coinbase txns in new block {current_blockheight}..."
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
                log.trace(
                    f"retrieving utxo(txid={txin_txid}, vout={txin_vout}) block index data..."
                )
                utxo_block = self.db.get_block(blockheaderhash=utxo_blockheaderhash)
                utxo_blockheight = utxo_block["blockheight"]
                log.trace(
                    f"utxo(txid={txin_txid}, vout={txin_vout}) block index data retrieved."
                )
                log.trace(
                    f"retrieving utxo(txid={txin_txid}, vout={txin_vout}) block data..."
                )
                cached_utxo_block_data = self._block_cache.get(utxo_blockheaderhash)
                if cached_utxo_block_data:
                    utxo_block_data = cached_utxo_block_data["block"]
                else:
                    utxo_block_data = self.get_block_data(
                        utxo_block["datafile"],
                        utxo_block["datafile_offset"],
                        cache=True,
                    )
                log.trace(
                    f"utxo(txid={txin_txid}, vout={txin_vout}) block data retrieved."
                )
                utxo_block_data_dict = utxo_block_data.dict()
                log.trace(
                    f"utxo(txid={txin_txid}, vout={txin_vout}) block data deserialized."
                )
                log.trace(f"filtering for utxo(txid={txin_txid}, vout={txin_vout}...")
                utxo_tx = next(
                    (t for t in utxo_block_data_dict["txns"] if t["txid"] == txin_txid)
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

                # this tx_in succeeds, update utxoset
                self.db.remove_from_utxoset(
                    utxo_block["blockheaderhash"], txin_txid, txin_vout, commit=False
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

        max_block_reward = self.get_block_reward() + miner_tips
        if coinbase_tx_txouts_total_value > max_block_reward:
            raise ConnectBlockError(
                f"block {current_block['blockheaderhash']} coinbase tx spends more than the max block reward"
            )
        log.debug(
            f"validated all of {len(current_block_data_dict['txns'])} txns in block {current_blockheight}."
        )
        self.db._curs.execute("COMMIT;")  # commit changes to utxoset in index db
        return True

    def get_block_reward(self) -> int:
        """
        get the block reward for the current block
        """
        blockheight = self.db.get_blockchain_height()
        reward = 50 * bits.constants.COIN
        reward >>= int(blockheight / 210000)
        return reward

    def get_next_nbits(self, proposed_block: Union[bytes, dict]) -> set:
        """
        Determine the allowed set of valid nbits for the next block

        Returns:
            set, valid nbits for next block
        """
        proposed_block = (
            proposed_block
            if type(dict)
            else bits.blockchain.block_deser(proposed_block)
        )

        current_blockheight = self.db.get_blockchain_height()
        current_block = self.db.get_block(current_blockheight)

        proposed_blockheight = current_blockheight + 1

        # used for testnet special rule (if applicable)
        # if no block mined in last 20 min, difficulty can be set to 1.0
        # https://en.bitcoin.it/wiki/Testnet
        # enforced below
        elapsed_time_for_last_block = proposed_block["nTime"] - current_block["nTime"]
        if proposed_blockheight % 2016:
            # not difficulty adjustment block

            if self.network == "testnet" and elapsed_time_for_last_block >= 1200:
                # testnet allows minimum difficulty when elapsed_time_for_last_block >= 1200
                return set([current_block["nBits"], "1d00ffff"])
            elif self.network == "testnet" and current_block["nBits"] == "1d00ffff":
                # tesnet is supposed to snap back to last non-minimum difficulty
                # the block after setting to minimum difficulty (allowed when last block mined >=20min)
                # if we're not in difficulty adjustment and elapsed time for last block is <20min
                # this also only applies when current_block["nBits"] == "1d00ffff",
                # so we check for the last non-min difficulty in this period and if None, we use min
                last_non_max_nbits = self.db.last_non_min_diff_in_diff_adj_period()
                next_nbits = last_non_max_nbits if last_non_max_nbits else "1d00ffff"
                return set([next_nbits])
            else:
                return set([current_block["nBits"]])
        else:
            # difficulty adjustment block
            current_target = bits.blockchain.target_threshold(
                bytes.fromhex(current_block["nBits"])[::-1]
            )
            current_difficulty = bits.blockchain.difficulty(
                current_target, network=self.network
            )

            block_0 = self.db.get_block(
                current_blockheight - 2015
            )  # first block of difficulty period

            elapsed_time = current_block["nTime"] - block_0["nTime"]

            new_difficulty = bits.blockchain.calculate_new_difficulty(
                elapsed_time, current_difficulty
            )
            new_target = bits.blockchain.target(new_difficulty, network=self.network)
            new_target_nbits = bits.blockchain.compact_nbits(new_target)[::-1].hex()

            if self.network == "testnet" and elapsed_time_for_last_block >= 1200:
                return set(["1d00ffff", new_target_nbits])
            else:
                return set([new_target_nbits])

    def median_time(self):
        """
        Return the median time of the last 11 blocks
        """
        current_blockheight = self.db.get_blockchain_height()
        if current_blockheight == 0:
            block_index_data = self.db.get_block(current_blockheight)
            return block_index_data["nTime"]
        times = []
        for i in range(min(current_blockheight, 11)):
            block_index_data = self.db.get_block(current_blockheight - i)
            t = block_index_data["nTime"]
            times.append(t)
        times = sorted(times)
        if len(times) % 2:
            # odd
            median = times[len(times) // 2]
        else:
            median = (times[len(times) // 2 - 1] + times[len(times) // 2]) // 2
        return median
