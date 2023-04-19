"""
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
"""
import hashlib
import os
import secrets
import unicodedata


def load_wordlist():
    with open(os.path.join(os.path.dirname(__file__), "english.txt")) as file_:
        english = file_.read()
    words = [word.strip() for word in english.splitlines()]
    return words


def calculate_mnemonic_phrase(entropy: bytes) -> str:
    """
    >>> calculate_mnemonic_phrase(bytes.fromhex("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b"))
    'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
    """
    strength = len(entropy) * 8
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            "entropy strength must be in range [128, 256] bits and multiple of 32"
        )

    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    words = load_wordlist()

    ENT = strength // 32
    checksum = hashlib.sha256(entropy).digest()[0] & (2**ENT - 1) << (8 - ENT)
    entropy = int.from_bytes(entropy, "big") << ENT
    entropy |= checksum >> 8 - ENT
    bit_groups = []  # groups of 11 bits
    idx = 0
    while idx < (strength + ENT) // 11:
        bit_group = (entropy >> idx * 11) & 0x7FF
        bit_groups.append(bit_group)
        idx += 1
    return " ".join([words[bit_group] for bit_group in reversed(bit_groups)])


def to_entropy(mnemonic: str) -> bytes:
    """
    Inverse of calculate_mnemonic_phrase(entropy)
    Get original entropy from mnemonic
    Args:
        mnemonic: str, mnemonic phrase

    >>> to_entropy("gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog").hex()
    '6610b25967cdcca9d59875f5cb50b0ea75433311869e930b'
    """
    words = mnemonic.split()
    if len(words) not in [12, 15, 18, 21, 24]:
        raise ValueError("word length does not indicate a valid entropy bit length")
    entropy_w_checksum_bitlen = len(words) * 11
    entropy_w_checksum_len = (entropy_w_checksum_bitlen + 7) // 8
    checksum_bitlen = len(words) // 3
    entropy_bitlen = entropy_w_checksum_bitlen - checksum_bitlen
    entropy_len = (entropy_bitlen + 7) // 8

    wordlist = load_wordlist()

    data = 0
    for idx, word in enumerate(reversed(words)):
        bit_group = wordlist.index(word)
        data |= bit_group << (idx * 11)

    checksum = (
        data.to_bytes(entropy_w_checksum_len, "big")[-1] & 2**checksum_bitlen - 1
    )
    entropy = data >> checksum_bitlen
    entropy = entropy.to_bytes(entropy_len, "big")
    checksum_check = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bitlen)
    assert checksum_check == checksum, "checksum validation error"
    return entropy


def to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Defined in BIP39
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
    """
    ITERATIONS = 2048
    return hashlib.pbkdf2_hmac(
        "sha512",
        unicodedata.normalize("NFKD", mnemonic).encode("utf-8"),
        unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8"),
        ITERATIONS,
    )
