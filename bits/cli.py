import argparse

from bits.btypes import pubkey_hash, bitcoin_address


def to_bitcoin_address(pubkey_hex: bytes, network: str = None) -> bytes:
    """
    Convert pubkey to bitcoin address
    Args:
        pubkey_: bytes, pubkey in hex
    """
    pkh = pubkey_hash(pubkey_hex)
    return bitcoin_address(pkh, network=network).decode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("pubkey", type=str, help="pubkey in hex format")
    parser.add_argument(
        "--network", type=str, default="mainnet", help="'mainnet' or 'testnet'"
    )
    args = parser.parse_args()

    if args.command == "to_bitcoin_address":
        pubkey = bytes.fromhex(args.pubkey)
        print(to_bitcoin_address(pubkey, network=args.network))
    else:
        raise ValueError("command not found")


if __name__ == "__main__":
    main()
