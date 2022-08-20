import argparse

from bits.utils import pubkey_hash, base58check
from bits.wallet.hd.bip32 import to_master_key, parse_256, point, ser_p
from bits.wallet.hd.bip39 import generate_mnemonic_phrase, to_seed


def to_bitcoin_address(pubkey_: bytes, network: str = None) -> str:
    """
    Convert pubkey to bitcoin address
    Args:
        pubkey_: bytes, pubkey in hex
        network: str, `mainnet` or `testnet`
    Returns:
        base58 encoded bitcoin address
    """
    pkh = pubkey_hash(pubkey_)
    if network == "mainnet":
        version = b"\x00"
    elif network == "testnet":
        version = b"\x6f"
    else:
        raise ValueError(f"unrecognized network: {network}")
    return base58check(version, pkh).decode("ascii")


def main():
    parser = argparse.ArgumentParser(prog="bits")
    sub_parser = parser.add_subparsers(dest="command")
    to_bitcoin_address_parser = sub_parser.add_parser("to_bitcoin_address")
    to_bitcoin_address_parser.add_argument(
        "pubkey", type=str, help="pubkey in hex format"
    )
    to_bitcoin_address_parser.add_argument(
        "--network", type=str, default="mainnet", help="'mainnet' or 'testnet'"
    )

    hd_parser = sub_parser.add_parser("hd")
    hd_sub_parser = hd_parser.add_argument("hd_command")

    args = parser.parse_args()

    if args.command == "to_bitcoin_address":
        pubkey = bytes.fromhex(args.pubkey)
        print(to_bitcoin_address(pubkey, network=args.network))
    elif args.command == "hd":
        if args.hd_command == "generate_mnemonic":
            print(generate_mnemonic_phrase())
        elif args.hd_command == "generate_master_keys":
            phrase = generate_mnemonic_phrase()
            seed = to_seed(phrase)
            master_key, master_chain_code = to_master_key(seed)

            # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
            version = b"\x04\x88\xAD\xE4"  # private mainnet
            xprv = base58check(
                version,
                b"\x00"  # depth, 0x00 for master key
                + b"\x00\x00\x00\x00"  # parent key fingerprint, 0x00000000 for master key
                + b"\x00\x00\x00\x00"  # child number, 0x00000000 for master key
                + master_chain_code
                + b"\x00"
                + master_key,
            ).decode("ascii")
            print(xprv)

            pubpoint_ = point(parse_256(master_key))
            version = b"\x04\x88\xB2\x1E"  # public mainnet
            xpub = base58check(
                version,
                b"\x00"
                + b"\x00\x00\x00\x00"
                + b"\x00\x00\x00\x00"
                + master_chain_code
                + ser_p(pubpoint_),
            ).decode("ascii")
            print(xpub)
        else:
            raise ValueError("hd command not found")
    else:
        raise ValueError("command not found")


if __name__ == "__main__":
    main()
