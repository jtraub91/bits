"""
P2P and stuff

https://developer.bitcoin.org/devguide/p2p_network.html
https://developer.bitcoin.org/reference/p2p_networking.html
https://en.bitcoin.it/wiki/Network
https://en.bitcoin.it/wiki/Protocol_documentation
"""
import asyncio
import logging
import socket
from typing import Union

from bits.utils import d_hash

GENESIS_BLOCK = b""


# Magic start strings
# https://github.com/bitcoin/bitcoin/blob/v23.0/src/chainparams.cpp#L102-L105
MAINNET_START = b"\xF9\xBE\xB4\xD9"
TESTNET_START = b"\x0B\x11\x09\x07"
REGTEST_START = b"\xFA\xBF\xB5\xDA"

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


def dns_seeds():
    return


def discover_nodes():
    pass


def connect_peer():
    return


def msg_ser(
    command: Union[str, bytes],
    payload: bytes = b"",
    start_string: bytes = MAINNET_START,
) -> bytes:
    """
    Serialized p2p message
    """
    if command not in COMMANDS:
        raise ValueError("invalid command")
    if len(payload) > MAX_SIZE:
        raise ValueError("payload exceeds MAX_SIZE")
    while len(command) < 12:
        command += b"\x00"
    payload_size = len(payload).to_bytes(32, "little")
    checksum = d_hash(payload)[:4]
    return start_string + command + payload_size + checksum


def start_node(host="localhost", port=8333, max_connections=5):
    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(max_connections)
    while True:
        client_sock, addr_info = sock.accept()
        print()
