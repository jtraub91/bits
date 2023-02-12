"""
Utils for various integrations with local bitcoind node 
"""
import logging
import time
from typing import Iterator
from typing import Optional

import bits.blockchain
import bits.keys
import bits.rpc
from bits.script.utils import null_data_script_pubkey
from bits.script.utils import p2pkh_script_pubkey
from bits.utils import d_hash
from bits.utils import pubkey_hash
from bits.utils import to_bitcoin_address
from bits.utils import wif_encode

log = logging.getLogger(__name__)


def median_time() -> int:
    """
    Returns the median time of the last 11 blocks
    """
    block_count = bits.rpc.rpc_method("getblockcount")
    times = []
    for i in range(11):
        block_hash = bits.rpc.rpc_method("getblockhash", block_count - i)
        block = bits.rpc.rpc_method("getblock", block_hash)
        t = block["time"]
        times.append(t)
    return sorted(times)[5]


def generate_funded_keys(
    count: int, compressed_pubkey: bool = False, network: str = "regtest"
) -> Iterator[tuple[bytes, bytes]]:
    """
    Generate keys which receive coinbase reward sent to its uncompressed p2pkh address
    Args:
        count: int, number of funded keys to generate
        compressed_pubkey: bool, wether key should correspond to compressed pubkey for recv addr
        network: str, bitcoin network
    Returns:
        iteration of tuples (key, addr)
    """
    keys_addrs = []
    for i in range(count):
        key = bits.keys.key()
        pubkey = bits.keys.pub(key, compressed=compressed_pubkey)
        wif_encoded_key = wif_encode(
            key, compressed_pubkey=compressed_pubkey, network=network
        )
        pk_hash = pubkey_hash(pubkey)
        addr = to_bitcoin_address(pk_hash, addr_type="p2pkh", network=network)

        mine_block(addr, network=network)

        keys_addrs.append((wif_encoded_key, addr))

    for key_addr in keys_addrs:
        yield key_addr


def mine_block(recv_addr: Optional[bytes] = b"", network: str = "regtest"):
    """
    Retrieve all raw mempool transactions and submit in a block
    Args:
        recv_addr: Optional[bytes], p2pkh addr to receive block reward
    """
    current_block_height = bits.rpc.rpc_method("getblockcount")
    current_block_hash = bits.rpc.rpc_method("getblockhash", current_block_height)
    current_block = bits.rpc.rpc_method("getblock", current_block_hash)
    current_block_time = current_block["time"]

    tgt_threshold = bits.blockchain.target_threshold(
        bytes.fromhex(current_block["bits"])
    )
    # current block is now previous block (and reverse byte order)
    prev_block_hash = bytes.fromhex(current_block["hash"])[::-1]
    prev_nbits = bytes.fromhex(current_block["bits"])[::-1]

    # gather raw mempool txns
    mempool_txids: list[str] = bits.rpc.rpc_method("getrawmempool")
    mempool_raw_txns: list[str] = [
        bits.rpc.rpc_method("getrawtransaction", txid) for txid in mempool_txids
    ]

    if recv_addr:
        pk_hash = bits.base58.base58check_decode(recv_addr)[1:]
        script_pubkey = p2pkh_script_pubkey(pk_hash)
    else:
        script_pubkey = null_data_script_pubkey(recv_addr)

    txns = [
        bits.tx.coinbase_tx(
            b"bits",
            script_pubkey,
            block_height=current_block_height + 1,
            network=network,
        )
    ] + [bytes.fromhex(raw_tx) for raw_tx in mempool_raw_txns]
    merkle_root_hash = bits.blockchain.merkle_root(txns)

    t = int(time.time())
    if current_block_height >= 10:
        median_time_ = median_time()
        if t <= median_time_:
            t = median_time_ + 1

    nonce = 0
    new_block_header = bits.blockchain.block_header(
        4,
        prev_block_hash,
        merkle_root_hash,
        t,
        prev_nbits,
        nonce,
    )
    new_block_hash = d_hash(new_block_header)

    log.info(f"Mining block {current_block_height + 1}...")
    while int.from_bytes(new_block_hash, "little") > tgt_threshold:
        nonce += 1
        new_block_header = bits.blockchain.block_header(
            4,
            prev_block_hash,
            merkle_root_hash,
            t,
            prev_nbits,
            nonce,
        )
        new_block_hash = d_hash(new_block_header)

    new_block = bits.blockchain.block_ser(
        new_block_header,
        txns,
    )
    ret = bits.rpc.rpc_method("submitblock", new_block.hex())
    if ret:
        raise ValueError(ret)
    log.info(
        f"Block {current_block_height + 1} submitted successfully. Coinbase sent to {recv_addr}"
    )
