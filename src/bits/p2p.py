"""
P2P and stuff

https://developer.bitcoin.org/devguide/p2p_network.html
https://developer.bitcoin.org/reference/p2p_networking.html
https://en.bitcoin.it/wiki/Network
https://en.bitcoin.it/wiki/Protocol_documentation
"""
import base64
import binascii
import logging
import os
import socket
import time
import xmlrpc.server
from collections import deque
from threading import Event
from threading import Thread
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import bits
from bits.blockchain import genesis_block


# Magic start strings
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L102-L105
MAINNET_START = b"\xF9\xBE\xB4\xD9"
TESTNET_START = b"\x0B\x11\x09\x07"
REGTEST_START = b"\xFA\xBF\xB5\xDA"

# default ports
MAINNET_PORT = 8333
TESTNET_PORT = 18333
REGTEST_PORT = 18444

MAGIC_START_BYTES = None

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


def set_magic_start_bytes(network: str = "mainnet"):
    global MAGIC_START_BYTES
    if network.lower() == "mainnet":
        MAGIC_START_BYTES = MAINNET_START
    elif network.lower() == "testnet":
        MAGIC_START_BYTES = TESTNET_START
    elif network.lower() == "regtest":
        MAGIC_START_BYTES = REGTEST_START
    else:
        raise ValueError(f"network not recognized: {network}")
    return True


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
) -> bytes:
    timestamp = int(time.time())
    addr_recv_services = 0x00
    addr_recv_ip_addr = "::ffff:127.0.0.1"
    addr_trans_ip_addr = "::ffff:127.0.0.1"
    nonce = 0
    user_agent = b"/bits:0.1.0/"
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
    block_header_hashes: List[bytes], protocol_version: int = 70015
) -> bytes:
    """ """
    stop_hash = b"\x00" * 32
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


def parse_payload(command, payload):
    parse_fn_name = f"parse_{command.decode('ascii')}_payload"
    parse_fn = globals().get(parse_fn_name)
    if parse_fn:
        return parse_fn(payload)
    else:
        log.debug(f"no parser {parse_fn_name}")


def write_blocks_to_disk(blocks: List[bytes], datadir: str):
    """
    Write blocks to disk

    observe max_blockfile_size &
    number files blk00000.dat, blk00001.dat, ...

    Args:
        blocks: List[bytes]
        datadir: str, path to blockchain datadir
    """
    if not os.path.exists(datadir):
        os.makedirs(datadir)

    dat_files = sorted([f for f in os.listdir(datadir) if f.endswith(".dat")])
    if not dat_files:
        filepath = os.path.join(datadir, "blk00000.dat")
    else:
        filepath = os.path.join(datadir, dat_files[-1])

    dat_file = open(filepath, "ab")
    for blk in blocks:
        blk_data = MAGIC_START_BYTES + len(blk).to_bytes(4, "little") + blk
        if len(blk_data) + dat_file.tell() <= MAX_BLOCKFILE_SIZE:
            dat_file.write(blk_data)
        else:
            dat_file.close()
            new_blk_no = (
                int(os.path.split(filepath)[-1].split(".dat")[0].split("blk")[-1]) + 1
            )
            filename = f"blk{new_blk_no.zfill(5)}.dat"
            filepath = os.path.join(datadir, filename)
            dat_file = open(filepath, "ab")
    dat_file.close()


class PeerThread(Thread):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exit_event = Event()

    def exit(self):
        self.exit_event.set()


class Peer:
    def __init__(self, host: Union[str, bytes], port: int):
        self.host = host
        self.port = port

        self.socket = socket.socket()
        self.connect_socket()

        self.thread = PeerThread(
            target=self.recv_loop,
        )

        self.unhandled_command_queue = deque([])
        self._last_recvd_msg_time = None

    def connect_socket(self):
        """
        Connect peer socket
        """
        self.socket.connect((self.host, self.port))
        self.socket.setblocking(True)
        self.socket.settimeout(5)
        log.info(f"socket connected to peer @ {self.host}:{self.port}")

    def start_thread(self):
        self.thread.start()

    def stop_thread(self):
        self.thread.exit()

    def save_version_data(self, data: dict):
        self.version_data = data

    def recv_msg(self) -> Tuple[bytes, bytes, bytes]:
        """
        Recv and deserialize message ( header + optional payload )
        """
        msg = b""
        while len(msg) != MSG_HEADER_LEN:
            msg += self.socket.recv(MSG_HEADER_LEN - len(msg))

        start_bytes = msg[:4]
        command = msg[4:16].rstrip(b"\x00")
        payload_size = int.from_bytes(msg[16:20], "little")
        checksum = msg[20:24]
        payload = msg[24:]
        if payload_size:
            while len(payload) != payload_size:
                payload += self.socket.recv(payload_size - len(payload))

        # sanity checks
        if len(payload) != payload_size:
            raise ValueError(
                f"payload_size ({payload_size}) does not match length of payload ({len(payload)})"
            )
        if checksum != bits.crypto.hash256(payload)[:4]:
            raise ValueError(
                f"checksum failed. {checksum} != {bits.crypto.hash256(payload)[:4]}"
            )
        if start_bytes != MAGIC_START_BYTES:
            raise ValueError(
                f"network mismatch - {start_bytes} not equal to magic start bytes {MAGIC_START_BYTES}"
            )
        log.info(
            f"received {len(start_bytes + command + payload)} bytes from peer @ {self.host}:{self.port}. command: {command}"
        )
        log.debug(f"payload: {payload}")
        self._last_recvd_msg_time = time.time()
        return start_bytes, command, payload

    def recv_loop(self):
        """
        Recv loop; receive msg, add to msg queue
        """
        while not self.thread.exit_event.is_set():
            try:
                start_bytes, command, payload = self.recv_msg()
                payload = parse_payload(command, payload)
                log.info(f"payload (parsed): {payload}")
                self.handle_command(command, payload)
            except TimeoutError:
                log.debug("recv msg timeout, continuing...")
                if time.time() - self._last_recvd_msg_time > 90 * 60:
                    # if it's been > 90 min since last message
                    self.stop_thread()
                continue
        log.debug("Exiting recv_loop...")
        self.socket.close()
        log.info(f"peer @ {self.host}:{self.port} socket is closed.")

    def send_command(self, command: bytes, payload: bytes):
        msg = msg_ser(MAGIC_START_BYTES, command, payload)
        self.socket.sendall(msg)

    ### handlers ###
    def handle_command(self, command: bytes, payload: dict):
        handle_fn_name = f"handle_{command.decode('ascii')}_command"
        handle_fn = getattr(self, handle_fn_name, None)
        if handle_fn:
            log.info(f"handling {command} command...")
            return handle_fn(command, payload)  # pylint: disable=not-callable
        else:
            log.warning(
                f"no handler {handle_fn_name}, adding to unhandled_command_queue"
            )
            self.unhandled_command_queue.append((command, payload))

    def handle_inv_command(self, command: bytes, payload: dict):
        count = payload["count"]
        if count == 500:
            recv_inventories = payload["inventory"]
            inventories = [
                inventory(inv["type_id"], inv["hash"].encode("ascii"))
                for inv in recv_inventories[:128]
            ]
            msg = msg_ser(MAGIC_START_BYTES, b"getdata", inv_payload(128, inventories))
            log.info("handle_inv_command: sending getdata command ...")
            self.socket.sendall(msg)

    def handle_feefilter_command(self, command: bytes, payload: dict):
        log.info("handle_feefilter_command: no action implemented")

    def handle_getheaders_command(self, command: bytes, payload: dict):
        msg = msg_ser(MAGIC_START_BYTES, "headers", b"")
        log.info(
            f"handle_getheaders_command: sending empty headers message to peer @ {self.host}:{self.port}..."
        )
        self.socket.sendall(msg)

    def handle_ping_command(self, command: bytes, payload: dict):
        """
        Handle ping command by sending a 'pong' message
        """
        msg = msg_ser(MAGIC_START_BYTES, b"pong", ping_payload(payload["nonce"]))
        log.info(
            f"handle_ping_command: sending pong to peer @ {self.host}:{self.port}..."
        )
        self.socket.sendall(msg)

    def handle_sendheaders_command(self, command: bytes, payload: dict):
        log.info("handle_sendheaders_command: no action implemented")


class Node:
    def __init__(
        self,
        seeds: List[str],
        datadir: str,
        protocol_version: int = 70015,
        services: int = NODE_NETWORK,
        relay: bool = True,
    ):
        """
        bits P2P node

        Args:
            seeds: list[str], list of seed nodes to connect to, <host:port> e.g. ["127.0.0.1:18443",]
            datadir: str, directory to store blockchain data
            protocol_version: int
            services: int
            relay: bool
        """
        self._peers = []
        self.seeds = seeds
        self.protocol_version = protocol_version
        self.services = services
        self.relay = relay
        self.user_agent = f"/bits:{bits.__version__}/".encode("utf8")
        self.datadir = datadir

    def connect_peer(self, peer: Peer):
        """
        Connect peer by performing version / verack handshake
        """
        log.info(f"sending version message to peer @ {peer.host}:{peer.port}...")
        local_host, local_port = peer.socket.getsockname()
        versionp = version_payload(
            0,
            peer.port,
            local_port,
            protocol_version=self.protocol_version,
            services=self.services,
            relay=self.relay,
        )
        msg = msg_ser(MAGIC_START_BYTES, b"version", versionp)
        peer.socket.sendall(msg)

        # wait for version message
        start_bytes, command, payload = peer.recv_msg()
        assert command == b"version", f"expected version command not {command}"
        payload = parse_payload(command, payload)
        log.debug(f"payload (parsed): {payload}")

        # save version payload peer data
        peer.save_version_data(payload)

        # send verack
        msg = msg_ser(MAGIC_START_BYTES, b"verack", b"")
        log.info(f"sending verack message to peer @ {peer.host}:{peer.port}...")
        peer.socket.sendall(msg)

        start_bytes, command, payload = peer.recv_msg()
        assert command == b"verack", f"expected verack command, not {command}"
        payload = parse_payload(command, payload)
        log.debug(f"payload (parsed): {payload}")

        log.info(
            f"connection handshake established for @ {peer.host}:{peer.port}. starting peer peer recv_loop thread..."
        )
        peer.start_thread()

    def start(self):
        for seed in self.seeds:
            host, port = seed.split(":")
            port = int(port)
            peer = Peer(host, port)
            self.connect_peer(peer)
            self._peers.append(peer)

    def ibd(self):
        """
        Initial Block Download
        """
        gb = genesis_block()
        write_blocks_to_disk([gb], self.datadir)
        msg = msg_ser(
            MAGIC_START_BYTES,
            b"getblocks",
            getblocks_payload([bits.crypto.hash256(gb[:80])]),
        )
        self._peers[0].socket.sendall(msg)

    def stop(self):
        for peer in self._peers:
            peer.stop_thread()  # should close socket too


set_magic_start_bytes()
