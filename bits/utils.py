import hashlib
from base58 import b58decode

def d_hash(msg: bytes) -> bytes:
    """
    Double sha256 hash of msg
    """
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

def pubkey_hash_from_bitcoin_address(baddr: bytes) -> bytes:
    """
    Return pubkeyhash from bitcoin address, with checksum verification
    """
    decoded_addr = b58decode(baddr)
    checksum = decoded_addr[-4:]
    checksum_check = hashlib.sha256(hashlib.sha256(decoded_addr[:-4]).digest()).digest()
    assert checksum == checksum_check[:4]
    return decoded_addr[1:-4]   # remove version byte and checksum

def pubkey_point_from_pubkey(pk: bytes) -> tuple:
    """
    Return int tuple of pubkey (x, y) from pubkey in hex format (compressed/uncompressed)
    """
    version = pk[0]
    pk_ = pk[1:]
    raise NotImplementedError

def secret_from_privkey(privkey: bytes) -> int:
    """
    Return secret as int from privkey as hex bytes
    """
    raise NotImplementedError
