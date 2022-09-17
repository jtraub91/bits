"""
blockchain lulz
"""


def genesis_block():
    version: int = 1
    prev_blockhash: bytes = b"\x00" * 32
    merkle_root_hash = None
    nTime = 1231006505
    nBits = 0x1D00FFFF
    nNonce = 2083236893
    return block(1, b"\x00" * 32, merkle_root_hash, nTime, nBits, nonce)


def block(version, prev_blockheaderhash, merkle_root_hash, time, nBits, nonce):
    return (
        version.to_bytes(4, "little")
        + prev_blockheaderhash
        + merkle_root_hash
        + time
        + nBits
        + nonce
    )
