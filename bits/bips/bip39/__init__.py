import hashlib
import secrets
import unicodedata


def load_wordlist():
    with open("bits/bips/bip39/english.txt") as file_:
        english = file_.read()
    words = [word.strip() for word in english.splitlines()]
    return words


def calculate_mnemonic_phrase(entropy: bytes):
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


def to_seed(mnemonic, passphrase: str = "") -> bytes:
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


def to_entropy():
    raise NotImplementedError
