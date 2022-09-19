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
import socket
import time
from queue import Queue
from threading import Thread
from typing import List
from typing import Tuple
from typing import Union

from bits.utils import compact_size_uint
from bits.utils import d_hash


# Magic start strings
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L102-L105
MAINNET_START = b"\xF9\xBE\xB4\xD9"
TESTNET_START = b"\x0B\x11\x09\x07"
REGTEST_START = b"\xFA\xBF\xB5\xDA"

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


log = logging.getLogger("p2p")
log.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
sh = logging.StreamHandler()
sh.setFormatter(formatter)
log.addHandler(sh)


def set_log_level(level: str):
    valid_log_levels = ["info", "debug", "warning", "critical", "error"]
    if level.lower() not in valid_log_levels:
        raise ValueError(f"level not valid: {level}")
    log.setLevel(getattr(logging, level.upper()))
    return True


def set_magic_start_bytes(network: str):
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


def dns_seeds():
    return


def discover_nodes():
    return


def connect_peer(host: Union[str, bytes], port: int) -> socket.socket:
    sock = socket.socket()
    sock.connect((host, port))
    log.info(f"connected to peer @ {host}:{port}")
    local_host, local_port = sock.getsockname()
    versionp = version_payload(0, port, local_port)
    msg = msg_ser(MAGIC_START_BYTES, b"version", versionp)
    log.info("sending version message...")
    sock.sendall(msg)
    return sock


def start_node(seeds: List[str], use_spv: bool = False):
    """
    Start p2p client / server (full) node
    Args:
        seeds: list, list of seeds; e.g. []
    """
    peer_sockets = {}
    peer_threads = []
    for peer_no, node in enumerate(seeds):
        host, port = node.split(":")
        port = int(port)
        peer_sockets[peer_no] = connect_peer(host, port)
        peer_threads.append(
            Thread(
                target=start_loop,
                args=(peer_sockets[peer_no],),
                kwargs={"blocking": True},
            )
        )
        peer_threads[peer_no].start()


def start_loop(sock: socket.socket, blocking: bool = True):
    sock.setblocking(blocking)
    while True:
        start_bytes, command, payload = recv_msg(sock)
        log.info(
            f"received {len(start_bytes + command + payload)} bytes. command: {command}"
        )
        log.debug(f"payload: {payload}")
        handle_message(sock, command, payload=payload)


def handle_version_command(sock: socket.socket, command: bytes, payload: dict):
    log.info(f"handling {command} command...")
    msg = msg_ser(MAGIC_START_BYTES, b"verack", b"")
    log.info("sending verack...")
    sock.sendall(msg)
    log.debug(f"sent serialized message: {msg}")
    log.info(f"TODO store connected peer version info: {payload}")


def handle_command(sock, command, payload):
    handle_fn_name = f"handle_{command.decode('ascii')}_command"
    handle_fn = globals().get(handle_fn_name)
    if handle_fn:
        return handle_fn(sock, command, payload)
    else:
        log.warning(f"no handler {handle_fn_name}")


def handle_message(sock: socket.socket, command: bytes, payload: bytes):
    if payload:
        payload = parse_payload(command, payload)
        log.info(f"received payload (parsed): {payload}")
    handle_command(sock, command, payload)


def initial_block_download():
    """
    IBD
    """
    pass


def recv_msg(sock: socket.socket) -> Tuple[bytes, bytes, bytes]:
    """
    Recv and deserialize message ( header + optional payload )
    """
    msg = b""
    while len(msg) != MSG_HEADER_LEN:
        msg += sock.recv(MSG_HEADER_LEN - len(msg))
        # log.info(msg)
    start_bytes = msg[:4]
    command = msg[4:16].rstrip(b"\x00")
    payload_size = int.from_bytes(msg[16:20], "little")
    checksum = msg[20:24]
    payload = msg[24:]
    if payload_size:
        payload = sock.recv(payload_size)
    if len(payload) != payload_size:
        raise ValueError("payload_size does not match length of payload")
    if checksum != d_hash(payload)[:4]:
        raise ValueError(f"checksum failed. {checksum} != {d_hash(payload)[:4]}")
    if start_bytes != MAGIC_START_BYTES:
        raise ValueError(
            f"network mismatch - {start_bytes} not equal to magic start bytes {MAGIC_START_BYTES}"
        )
    return start_bytes, command, payload


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
    checksum = d_hash(payload)[:4]
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
    user_agent_bytes = 0x00
    user_agent = ""
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
        + compact_size_uint(user_agent_bytes)
        + user_agent.encode("ascii")
        + start_height.to_bytes(4, "little")
    )
    msg += b"\x01" if relay else b"\x00"
    return msg


def ping_payload(nonce: int) -> bytes:
    return nonce.to_bytes(8, "little")


def parse_ping_payload(payload: bytes) -> dict:
    return {"nonce": int.from_bytes(payload, "little")}


# pong payload same as ping


def getheaders_payload(
    protocol_version: int,
    hash_count: int,
    block_header_hashes: List[bytes],
    stop_hash: bytes,
) -> bytes:
    return (
        protocol_version.to_bytes(4, "little")
        + compact_size_uint(hash_count)
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


# version
# verack
# sendheaders
# sendcmpct
# ping
# getheaders
# feefilter
# inv


def parse_payload(command, payload):
    parse_fn_name = f"parse_{command.decode('ascii')}_payload"
    parse_fn = globals().get(parse_fn_name)
    if parse_fn:
        return parse_fn(payload)
    else:
        log.warning(f"no parser {parse_fn_name}")


class Node:
    def __init__(self, peers: List[Tuple[str, int]]):
        self.peers = peers
