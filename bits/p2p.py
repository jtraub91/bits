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
from typing import Tuple
from typing import Union

from bits.utils import compact_size_uint
from bits.utils import d_hash

GENESIS_BLOCK = b""


# Magic start strings
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L102-L105
MAINNET_START = b"\xF9\xBE\xB4\xD9"
TESTNET_START = b"\x0B\x11\x09\x07"
REGTEST_START = b"\xFA\xBF\xB5\xDA"

MAGIC_START_BYTES = None

# https://github.com/bitcoin/bitcoin/blob/v23.0/src/serialize.h#L31
MAX_SIZE = 0x02000000

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

log = logging.getLogger("p2p")
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
sh = logging.StreamHandler()
sh.setFormatter(formatter)
log.addHandler(sh)


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


def connect_peer(host: Union[str, bytes], port: int):
    sock = socket.socket()
    sock.connect((host, port))
    log.info(f"connected to peer @ {host}:{port}")
    local_host, local_port = sock.getsockname()
    versionp = version_payload(0, port, local_port)
    msg = msg_ser(MAGIC_START_BYTES, b"version", versionp)
    sock.sendall(msg)

    recv_bytes = sock.recv(24)
    if recv_bytes:
        recv_start_bytes, recv_command, payload = msg_deser(recv_bytes)
        if recv_start_bytes != MAGIC_START_BYTES:
            log.error(f"network mismatch start bytes: {recv_start_bytes}")
            sock.close()
            log.info("peer disconnected")
            return
        log.debug(f"recv message: {recv_command}")
        payload_size = len(payload)
        log.debug(f"recv payload size (bytes): {payload_size}")

        checksum = recv_bytes[20:]
        payload = sock.recv(payload_size)
        log.debug(f"recv payload: {payload}")
        checksum_check = d_hash(payload)[:4]
        if checksum != checksum_check:
            log.error(f"checksum failed, expected {checksum_check}")
            sock.close()
            log.info("peer disconnected")
            return

        handle_message(recv_command)

    return sock


def start_loop(sock):
    while True:
        recv_bytes = sock.recv(24)
        if recv_bytes:
            start_bytes, command, payload_size = msg_deser(recv_bytes)
            if start_bytes != MAGIC_START_BYTES:
                log.error(f"network mismatch start bytes: {start_bytes}")
                sock.close()
                log.info("peer disconnected")
                return
            log.debug(f"command: {command}")
            payload_size = len(payload)
            log.debug(f"recv payload size (bytes): {payload_size}")

            checksum = recv_bytes[20:]
            payload = sock.recv(payload_size)
            log.debug(f"recv payload: {payload}")
            checksum_check = d_hash(payload)[:4]
            if checksum != checksum_check:
                log.error(f"checksum failed, expected {checksum_check}")
                sock.close()
                log.info("peer disconnected")
                return

            handle_message(recv_command)


def recv_message(sock):
    return sock.recv(24)


def handle_message(command: bytes):
    if command == b"version":
        log.debug(f"recv payload (parsed): {parse_version_payload(payload)}")
        msg = msg_ser(MAGIC_START_BYTES, b"verack", b"")
        log.info("sending verack in response to received version command...")
        sock.sendall(msg)
    elif command == b"getheaders":
        log.debug(f"recv payload (parsed): {parse_getheaders_payload(payload)}")


def start_node(use_spv: bool = False):
    """
    Start p2p client / server (full) node
    from seed nodes as defined in bits/config.json
    """
    with open("bits/config.json") as config_file:
        config = json.load(config_file)
    peer_sockets = {}
    for peer_no, node in enumerate(config["seedNodes"]):
        host, port = node.split(":")
        port = int(port)
        peer_sockets[peer_no] = connect_peer(host, port)


def msg_header_deser(msg: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Deserialize message header (w optional payload)
    """
    start_bytes = msg[:4]
    command = msg[4:16].rstrip(b"\x00")
    payload_size = int.from_bytes(msg[16:20], "little")
    checksum = msg[20:24]
    payload = msg[24:]
    if len(payload) and len(payload) != payload_size:
        raise ValueError("payload_size does not match length of payload")
    if checksum != d_hash(payload)[:4]:
        raise ValueError("checksum failed")
    ret = start_bytes, command, payload if payload else payload_size


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


def parse_ping_payload(payload: bytes) -> int:
    return int.from_bytes(payload, "little")


# pong payload same as ping


def getheaders_payload(
    protocol_version: int,
    hash_count: int,
    block_header_hashes: list[bytes],
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
            block_header_hashes[32 * i : 32 * (i + 1)]
            for i in range(1, 1 + len(block_header_hashes) // 32)
        ]
        parsed_payload["stop_hash"] = payload[
            index + hash_count * 32 : index + hash_count * 32 + 32
        ]
        if payload[index + hash_count * 32 + 32 :]:
            raise ValueError(f"parse error, data longer than expected: {len(payload)}")
    else:
        parsed_payload["stop_hash"] = payload[index : index + 32]
        if payload[index + 32 :]:
            raise ValueError(f"parse error, data longer than expected: {len(payload)}")
    return parsed_payload
