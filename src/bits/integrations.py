"""
Utils for various integrations with local bitcoind node 
"""
import logging
import time
import typing

import bits.blockchain
import bits.constants
import bits.keys
import bits.rpc
import bits.script

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def median_time(
    rpc_url: str = "", rpc_datadir: str = "", rpc_user: str = "", rpc_password: str = ""
) -> int:
    """
    Returns the median time of the last 11 blocks
    """
    rpc_kwargs = {
        "rpc_url": rpc_url,
        "rpc_datadir": rpc_datadir,
        "rpc_user": rpc_user,
        "rpc_password": rpc_password,
    }
    block_count = bits.rpc.rpc_method("getblockcount", **rpc_kwargs)
    block_hash = bits.rpc.rpc_method("getblockhash", block_count, **rpc_kwargs)
    block = bits.rpc.rpc_method("getblock", block_hash, **rpc_kwargs)
    if block_count == 0:
        return block["time"]
    times = []
    for i in range(min(block_count, 11)):
        block_hash = bits.rpc.rpc_method("getblockhash", block_count - i, **rpc_kwargs)
        block = bits.rpc.rpc_method("getblock", block_hash, **rpc_kwargs)
        t = block["time"]
        times.append(t)
    times = sorted(times)
    if len(times) % 2:
        # odd
        median = times[len(times) // 2]
    else:
        median = (times[len(times) // 2 - 1] + times[len(times) // 2]) // 2
    return median


def generate_funded_keys(
    count: int,
    compressed_pubkey: bool = False,
    network: str = "regtest",
    rpc_url: str = "",
    rpc_datadir: str = "",
    rpc_user: str = "",
    rpc_password: str = "",
) -> typing.Iterator[typing.Tuple[bytes, bytes]]:
    """
    Generate keys which receive coinbase reward sent to p2pkh address
    Args:
        count: int, number of funded keys to generate
        compressed_pubkey: bool, wether key should correspond to compressed pubkey for recv addr
        network: str, bitcoin network
    Returns:
        iterator of tuples (key, addr)
    """
    keys_addrs = []
    for i in range(count):
        key = bits.keys.key()
        pubkey = bits.keys.pub(key, compressed=compressed_pubkey)
        wif_encoded_key = bits.wif_encode(
            key, network=network, data=b"\x01" if compressed_pubkey else b""
        )
        pk_hash = bits.hash160(pubkey)
        addr = bits.to_bitcoin_address(pk_hash, addr_type="p2pkh", network=network)

        mine_block(
            addr,
            rpc_url=rpc_url,
            rpc_datadir=rpc_datadir,
            rpc_user=rpc_user,
            rpc_password=rpc_password,
        )

        keys_addrs.append((wif_encoded_key, addr))

    for key_addr in keys_addrs:
        yield key_addr


def mine_block(
    recv_addr: bytes,
    rpc_url: str = "",
    rpc_datadir: str = "",
    rpc_user: str = "",
    rpc_password: str = "",
):
    """
    Retrieve all raw mempool transactions and submit in a block.
    Regtest mode is inferred from getdifficulty rpc.
    Commits to witness root per BIP 141 via coinbase tx, if necessary
    Args:
        recv_addr: bytes, addr to receive block reward
    """
    rpc_kwargs = {
        "rpc_url": rpc_url,
        "rpc_datadir": rpc_datadir,
        "rpc_user": rpc_user,
        "rpc_password": rpc_password,
    }
    current_difficulty = bits.rpc.rpc_method("getdifficulty", **rpc_kwargs)
    is_regtest = True if current_difficulty < 1e-8 else False
    if is_regtest:
        log.debug(
            f"regtest mode inferred from rpc getdifficulty = {current_difficulty}"
        )

    current_block_height = bits.rpc.rpc_method("getblockcount", **rpc_kwargs)
    current_block_hash = bits.rpc.rpc_method(
        "getblockhash", current_block_height, **rpc_kwargs
    )
    current_block = bits.rpc.rpc_method("getblock", current_block_hash, **rpc_kwargs)
    current_block_time = current_block["time"]

    tgt_threshold = bits.blockchain.target_threshold(
        bytes.fromhex(current_block["bits"])
    )
    # current block is now previous block (and reverse byte order)
    prev_block_hash = bytes.fromhex(current_block["hash"])[::-1]
    prev_nbits = bytes.fromhex(current_block["bits"])[::-1]

    # gather raw mempool txns
    mempool_txids: typing.List[str] = bits.rpc.rpc_method("getrawmempool", **rpc_kwargs)
    mempool_raw_txns: typing.List[str] = [
        bits.rpc.rpc_method("getrawtransaction", txid, **rpc_kwargs)
        for txid in mempool_txids
    ]

    script_pubkey = bits.script.scriptpubkey(recv_addr)

    must_commit_wtxid = False  # bool if block must include witness commitment
    wtxids = [b"\x00" * 32]  # coinbase tx wtxid assumed to be 0s
    for raw_tx in mempool_raw_txns:
        tx_ = bytes.fromhex(raw_tx)
        deserialized_tx, _ = bits.tx.tx_deser(tx_)
        txid_ = bytes.fromhex(deserialized_tx["txid"])
        wtxid_ = bytes.fromhex(deserialized_tx["wtxid"])
        if txid_ != wtxid_:
            # mempool has segwit tx, must commit to wtxid per BIP 141
            must_commit_wtxid = True
        wtxids.append(bytes.fromhex(deserialized_tx["wtxid"]))
    # commit to wtxid per BIP141
    # https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#commitment-structure
    witness_merkle_root_hash = bits.blockchain.merkle_root(wtxids)
    witness_merkle_root_hash = bits.hash256(
        witness_merkle_root_hash + bits.constants.WITNESS_RESERVED_VALUE
    )

    # form txns with witness commitment, if necessary
    txns = [
        bits.tx.coinbase_tx(
            b"bits",
            script_pubkey,
            block_height=current_block_height + 1,
            regtest=is_regtest,
            witness_merkle_root_hash=witness_merkle_root_hash
            if must_commit_wtxid
            else None,
        )
    ] + [bytes.fromhex(raw_tx) for raw_tx in mempool_raw_txns]

    # now calculate txid merkle root
    txids = []
    for tx_ in txns:
        deserialized_tx, _ = bits.tx.tx_deser(tx_)
        txids.append(bytes.fromhex(deserialized_tx["txid"]))
    merkle_root_hash = bits.blockchain.merkle_root(txids)

    t = int(time.time())
    median_time_ = median_time(**rpc_kwargs)
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
    new_block_hash = bits.hash256(new_block_header)

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
        new_block_hash = bits.hash256(new_block_header)

    new_block = bits.blockchain.block_ser(
        new_block_header,
        txns,
    )
    log.debug(f"submitting block ... {new_block.hex()}")
    ret = bits.rpc.rpc_method("submitblock", new_block.hex(), **rpc_kwargs)
    if ret:
        raise ValueError(ret)
    log.info(
        f"Block {current_block_height + 1} submitted successfully. Coinbase sent to {recv_addr}"
    )
