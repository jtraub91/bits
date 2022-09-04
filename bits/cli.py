import argparse
from argparse import RawDescriptionHelpFormatter

from bits.bips.bip32 import parse_256
from bits.bips.bip32 import point
from bits.bips.bip32 import ser_p
from bits.bips.bip32 import to_master_key
from bits.bips.bip39 import generate_mnemonic_phrase
from bits.bips.bip39 import to_seed
from bits.utils import base58check
from bits.utils import pubkey_hash
from bits.wallet.hd import HD


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
    parser = argparse.ArgumentParser(
        prog="bits",
        formatter_class=RawDescriptionHelpFormatter,
        description="111101111111111011111\n100010010000100100000\n100010010000100100000\n111110010000100011110\n100010010000100000001\n100010010000100000001\n111111111100100111110",
    )
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
    if not args.command:
        parser.print_help()
    elif args.command == "to_bitcoin_address":
        pubkey = bytes.fromhex(args.pubkey)
        print(to_bitcoin_address(pubkey, network=args.network))
    elif args.command == "hd":
        if args.hd_command == "generate":
            print(generate_mnemonic_phrase())
        elif args.hd_command == "generate_root_keys":
            phrase = generate_mnemonic_phrase()
            hd = HD.from_mnemonic(phrase)
            xprv, xpub = hd.get_root_keys()
            print(xprv)
            print(xpub)
        elif args.hd_command == "createwallet":
            raise NotImplementedError
        else:
            raise ValueError("hd command not found")
    else:
        raise ValueError("command not found")


if __name__ == "__main__":
    main()
