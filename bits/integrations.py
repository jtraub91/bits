"""
Utils for various integrations with local bitcoind node 
"""
import time

import bits.blockchain
import bits.keys
import bits.rpc
from bits.script.utils import p2pkh_script_pubkey
from bits.utils import d_hash
from bits.utils import pubkey_hash


def funded_keys(count: int, network: str = "regtest"):
    """
    Generate keys which receive coinbase reward sent to its uncompressed p2pkh address
    """
    bits.load_config()
    rpc_kwargs = {
        "rpc_url": bits.bitsconfig["rpcurl"],
        "rpc_user": bits.bitsconfig["rpcuser"],
        "rpc_password": bits.bitsconfig["rpcpassword"],
    }
    keys = []

    # use current timestamp on regtest and just incremement by 1 each iteration
    # to avoid time-too-old response from bitcoind
    t = int(time.time())
    for i in range(count):
        key = bits.keys.key()
        pubkey = bits.keys.pub(key)
        keys.append(key)

        current_block_height = bits.rpc.rpc_method("getblockcount", **rpc_kwargs)
        current_block_hash = bits.rpc.rpc_method(
            "getblockhash", current_block_height, **rpc_kwargs
        )
        current_block = bits.rpc.rpc_method(
            "getblock", current_block_hash, **rpc_kwargs
        )

        tgt_threshold = bits.blockchain.target_threshold(
            bytes.fromhex(current_block["bits"])
        )

        # current block is now previous block (and reverse byte order)
        prev_block_hash = bytes.fromhex(current_block["hash"])[::-1]
        prev_nbits = bytes.fromhex(current_block["bits"])[::-1]

        pk_hash = pubkey_hash(pubkey)
        script_pubkey = p2pkh_script_pubkey(pk_hash)
        txns = [
            bits.tx.coinbase_tx(
                b"bits",
                script_pubkey,
                block_height=current_block_height + 1,
                network=network,
            )
        ]
        merkle_root_hash = bits.blockchain.merkle_root(txns)

        t += 1
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
        ret = bits.rpc.rpc_method("submitblock", new_block.hex(), **rpc_kwargs)
        if ret:
            raise ValueError(ret)
        yield key
