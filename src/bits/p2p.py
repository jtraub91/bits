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
import logging
import os
import socket
import time
from asyncio import StreamReader
from asyncio import StreamWriter
from collections import deque
from threading import Event
from threading import Thread
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import bits
from bits.blockchain import genesis_block


BITS_USER_AGENT = f"/bits:{bits.__version__}/".encode("utf8")

# Magic start strings
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L102-L105
MAINNET_START = b"\xF9\xBE\xB4\xD9"
TESTNET_START = b"\x0B\x11\x09\x07"
REGTEST_START = b"\xFA\xBF\xB5\xDA"

# default ports
MAINNET_PORT = 8333
TESTNET_PORT = 18333
REGTEST_PORT = 18444

# https://github.com/bitcoin/bitcoin/blob/v23.0/src/serialize.h#L31
MAX_SIZE = 0x02000000

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


# https://github.com/bitcoin/bitcoin/blob/v23.0/src/node/blockstorage.h#L43
MAX_BLOCKFILE_SIZE = 0x8000000  # 128 MiB


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


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
    if len(payload) > MAX_SIZE:
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
        "addr_recv_ip_addr": versionpayload_[28:44].decode("ascii"),
        "addr_recv_port": int.from_bytes(versionpayload_[44:46], "big"),
        "addr_trans_services": int.from_bytes(versionpayload_[46:54], "little"),
        "addr_trans_ip_addr": versionpayload_[54:70].decode("ascii"),
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
        parsed_payload["user_agent"] = versionpayload_[81 : 81 + user_agent_len]
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
        + user_agent
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


def inv_payload(count: int, inventories: List[bytes]) -> bytes:
    return bits.compact_size_uint(count) + b"".join(inventories)


def inventory(type_id: str, hash: bytes) -> bytes:
    """
    inventory data structure
    https://developer.bitcoin.org/glossary.html#term-Inventory
    """
    return int.to_bytes(INVENTORY_TYPE_ID[type_id.upper()], 4, "little") + hash


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
    ipv6 = ip_addr[:12]
    ipv4 = ip_addr[12:]

    ipv6_str = ""
    for n in range(6):
        nibble = ipv6[2 * n : 2 * n + 2]
        if nibble != b"\x00\x00":
            ipv6_str += nibble.hex().upper()
        else:
            if ipv6_str[-2:] != "::":
                ipv6_str += ":"

    return f"{ipv6_str}:{ipv4[0]}.{ipv4[1]}.{ipv4[2]}.{ipv4[3]}"


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
    def __init__(self, host: Union[str, bytes], port: int, network: str):
        self.host = host
        self.port = port
        if network.lower() == "mainnet":
            self.magic_start_bytes = MAINNET_START
        elif network.lower() == "testnet":
            self.magic_start_bytes = TESTNET_START
        elif network.lower() == "regtest":
            self.magic_start_bytes = REGTEST_START
        else:
            raise ValueError(f"network not recognized: {network}")

        self._last_recv_msg_time: float = None
        self.data = {}

        self.reader: StreamReader = None
        self.writer: StreamWriter = None

        self.exit_event = Event()

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
        payload = parse_payload(command, payload)
        log.info(
            f"read {len(start_bytes + command + payload)} bytes from peer @ {self.host}:{self.port}. command: {command}, payload: {payload}"
        )
        self._last_recv_msg_time = time.time()

        return start_bytes, command, payload

    def save_data(self, key: str, value: Union[str, list, dict, int, float]):
        log.info(f"saving {key} data for peer @ {self.host}:{self.port}...")
        self.data.update({key: value})

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
        protocol_version: int = 70015,
        services: int = NODE_NETWORK,
        relay: bool = True,
        user_agent: bytes = BITS_USER_AGENT,
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
        self._id = bits.keys.key().hex()  # peer id
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
            self.magic_start_bytes = MAINNET_START
        elif network.lower() == "testnet":
            self.magic_start_bytes = TESTNET_START
        elif network.lower() == "regtest":
            self.magic_start_bytes = REGTEST_START
        else:
            raise ValueError(f"network not recognized: {network}")
        self.network = network

        block_files = os.listdir(self.blocksdir)
        if not block_files:
            # write genesis block
            gb = genesis_block()
            self.write_blocks_to_disk([gb])

        self.message_queue = deque([])

        self.peers: list[Peer] = []
        self.addrs = {}

        self.exit_event = Event()

    def setup_logfile(self, filename: str, log_level: str):
        """
        add FileHandler to enable p2p logs
        """
        global log
        fh = logging.FileHandler(filename, "a")
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"
        )
        fh.setFormatter(formatter)
        fh.setLevel(getattr(logging, log_level.upper()))
        log.addHandler(fh)

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
        payload = parse_payload(command, payload)
        log.debug(f"payload (parsed): {payload}")

        # save version payload peer data
        peer.save_data("version", payload)

        # send verack
        await peer.send_command(b"verack")

        start_bytes, command, payload = await peer.recv_msg()
        assert command == b"verack", f"expected verack command, not {command}"
        payload = parse_payload(command, payload)
        log.debug(f"payload (parsed): {payload}")
        log.info(f"connection handshake established for @ {peer.host}:{peer.port}")

    async def connect_seeds(self):
        """
        Connect seeds as peers, and schedule outgoing peer recv loop task
        """
        for seed in self.seeds:
            host, port = seed.split(":")
            port = int(port)
            peer = Peer(host, port, self.network)
            await peer.connect()
            await self.connect_to_peer(peer)
            self.peers.append(peer)
            asyncio.create_task(self.outgoing_peer_recv_loop(peer))

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
        log.info(f"exiting peer recv loop for peer @ {peer.host}:{peer.port}")
        await peer.close()
        log.info(f"peer @ {peer.host}:{peer.port} socket is closed.")

    async def incoming_peer_server(self):
        # TODO
        return

    async def message_handler_loop(self):
        while not self.exit_event.is_set():
            if self.message_queue:
                peer, command, payload = self.message_queue.popleft()
                asyncio.create_task(self.handle_command(peer, command, payload))
            await asyncio.sleep(1)

    ### handlers ###
    async def handle_command(self, peer: Peer, command: bytes, payload: dict):
        handle_fn_name = f"handle_{command.decode('utf8')}_command"
        handle_fn = getattr(self, handle_fn_name, None)
        if handle_fn:
            log.info(f"handling {command.decode('utf8')} command...")
            await handle_fn(peer, command, payload)  # pylint: disable=not-callable
        else:
            self.message_queue.append((peer, command, payload))
            log.warning(
                f"no handler {handle_fn_name}, for {command.decode('utf8')} command"
            )

    async def handle_addr_command(self, peer: Peer, command: bytes, payload: dict):
        peer.save_data("addr", payload)

    async def handle_inv_command(self, peer: Peer, command: bytes, payload: dict):
        count = payload["count"]
        recv_inventories = payload["inventory"]
        inventories = [
            inventory(inv["type_id"], inv["hash"].encode("ascii"))
            for inv in recv_inventories[:128]
        ]
        await peer.send_command(b"getdata", inv_payload(len(inventories), inventories))

        if count > 128:
            for inv in recv_inventories[128:]:
                inventories = [inventory(inv["type_id"], inv["hash"].encode("ascii"))]
                await peer.send_command(b"getdata", inv_payload(1, inventories))

    def handle_block_command(self):
        return

    # def handle_getheaders_command(self, command: bytes, payload: dict):
    #     msg = msg_ser(self.magic_start_bytes, "headers", b"")
    #     log.info(
    #         f"handle_getheaders_command: sending empty headers message to peer @ {self.host}:{self.port}..."
    #     )
    #     self.socket.sendall(msg)

    async def handle_ping_command(self, peer: Peer, command: bytes, payload: dict):
        """
        Handle ping command by sending a 'pong' message
        """
        await peer.send_command(b"pong", ping_payload(payload["nonce"]))

    async def main(self):
        await self.connect_seeds()
        asyncio.create_task(self.main_loop())
        await self.message_handler_loop()

    def run(self):
        asyncio.run(self.main())
        log.info("node stopped.")

    def start(self):
        self.exit_event.clear()
        self._thread = Thread(target=self.run)
        self._thread.start()

    def stop(self):
        self.exit_event.set()
        log.info("node exit event is set")

    async def main_loop(self):
        for peer in self.peers:
            await peer.send_command(b"getaddr")

        # store addrs info from all peers to db?
        # how to decide which peers to connect from
        # new config option for max outgoing connections
        # need to eventual persist to disk, key-value, sqlite, pickle?

        # while not self.exit_event.is_set():

        await self.ibd()

    async def ibd(self):
        """
        Initial Block Download

        blocks first method, for simplicity
        https://developer.bitcoin.org/devguide/p2p_network.html#blocks-first
        """
        # parse latest dat file for most recent block (which should be genesis block for this blocks-first ibd)
        blk_files = sorted(os.listdir(self.blocksdir))
        blocks = self.parse_dat_file(os.path.join(self.blocksdir, blk_files[-1]))
        most_recent_block = blocks[-1]
        gb = genesis_block()
        assert most_recent_block == gb, "most recent doesn't match genesis block"

        sync_node = self.peers[0]
        await sync_node.send_command(
            b"getblocks",
            getblocks_payload([bits.crypto.hash256(most_recent_block[:80])]),
        )

    def write_blocks_to_disk(self, blocks: List[bytes]):
        """
        Write blocks to disk

        observe max_blockfile_size &
        number files blk00000.dat, blk00001.dat, ...

        Args:
            blocks: List[bytes]
        """
        dat_files = sorted(
            [f for f in os.listdir(self.blocksdir) if f.endswith(".dat")]
        )
        if not dat_files:
            filepath = os.path.join(self.blocksdir, "blk00000.dat")
        else:
            filepath = os.path.join(self.blocksdir, dat_files[-1])

        dat_file = open(filepath, "ab")
        for blk in blocks:
            blk_data = self.magic_start_bytes + len(blk).to_bytes(4, "little") + blk
            if len(blk_data) + dat_file.tell() <= MAX_BLOCKFILE_SIZE:
                dat_file.write(blk_data)
            else:
                dat_file.close()
                new_blk_no = (
                    int(os.path.split(filepath)[-1].split(".dat")[0].split("blk")[-1])
                    + 1
                )
                filename = f"blk{new_blk_no.zfill(5)}.dat"
                filepath = os.path.join(self.blocksdir, filename)
                dat_file = open(filepath, "ab")
                dat_file.write(blk_data)
        dat_file.close()

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
