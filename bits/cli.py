import argparse
import os
import random
from argparse import RawDescriptionHelpFormatter

from bits.bips.bip32 import parse_256
from bits.bips.bip32 import point
from bits.bips.bip32 import ser_p
from bits.bips.bip32 import to_master_key
from bits.bips.bip39 import generate_mnemonic_phrase
from bits.bips.bip39 import to_seed
from bits.openssl import genkey
from bits.openssl import public_pem_from_secret_pem
from bits.p2p import connect_peer
from bits.p2p import set_log_level
from bits.p2p import set_magic_start_bytes
from bits.p2p import start_node
from bits.utils import pubkey_from_pem
from bits.utils import pubkey_hash
from bits.utils import to_bitcoin_address
from bits.wallet.hd import HD


def main():
    # terminal_size = os.get_terminal_size()
    # no_of_rows = 21
    # desc = ""
    # for row in range(no_of_rows):
    #     for col in range(terminal_size.columns):
    #         desc += str(random.randint(0, 1))
    #     desc += "\n"
    parser = argparse.ArgumentParser(
        prog="bits",
        formatter_class=RawDescriptionHelpFormatter,
        # description=desc,
    )
    parser.add_argument(
        "--network",
        "-N",
        type=str,
        default="mainnet",
        help="'mainnet', 'testnet', or 'regtest'",
    )
    sub_parser = parser.add_subparsers(dest="command")
    to_bitcoin_address_parser = sub_parser.add_parser("to_bitcoin_address")
    to_bitcoin_address_parser.add_argument(
        "pubkey", type=str, help="pubkey in hex format", nargs="?"
    )
    to_bitcoin_address_parser.add_argument(
        "--from-file", type=str, help="path to public key pem file"
    )
    wallet_parser = sub_parser.add_parser("createwallet")
    genkey_parser = sub_parser.add_parser("genkey")
    hd_parser = sub_parser.add_parser("hd")
    hd_sub_parser = hd_parser.add_argument("hd_command")

    p2p_parser = sub_parser.add_parser("p2p")
    p2p_sub_parser = p2p_parser.add_argument("p2p_command")
    p2p_parser.add_argument("-H", "--host", type=str, help="host to connect to")
    p2p_parser.add_argument("-p", "--port", type=int, help="port to connect to")
    p2p_parser.add_argument(
        "--seeds", type=str, help="comma separated list of seed nodes"
    )
    p2p_parser.add_argument(
        "-L", "-l", dest="log_level", type=str, default="info", help="set log level"
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
    elif args.command == "createwallet":
        wallet_type = input("What type of wallet do you want to create? (JBOK or HD): ")
        if wallet_type.lower() not in ["jbok", "hd"]:
            print(f"choice not recognized: {wallet_type}")
            exit()
        wallet_name = input("Specify wallet name: ")
        if os.path.exists(f".bits/wallets/jbok/{wallet_name}"):
            print(f"{wallet_name} {wallet_type} wallet already exists. Exiting... ")
            exit()
        else:
            wallet_dir = f".bits/wallets/jbok/{wallet_name}"
            os.makedirs(wallet_dir)

            secret_pem = f".bits/wallets/jbok/{wallet_name}/secret0.pem"
            public_pem = f".bits/wallets/jbok/{wallet_name}/public0.pem"

            genkey(save_as=secret_pem)
            print(f"Secret key saved to {secret_pem}")

            public_pem_from_secret_pem(secret_pem, save_as=public_pem, compressed=True)
            print(f"Public key saved to {public_pem}")

    elif args.command == "genkey":
        print(genkey())
    elif args.command == "to_bitcoin_address":
        if args.from_file:
            with open(args.from_file) as pem_file:
                pubkey = pubkey_from_pem(pem_file.read(), compressed=True)
        else:
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
    elif args.command == "p2p":
        set_log_level(args.log_level)
        if args.p2p_command == "start":
            # bits --network testnet p2p start --seeds "host1:port1,host2:port2"
            set_magic_start_bytes(args.network)
            start_node(args.seeds.split(","))
        else:
            raise ValueError("p2p command not found")
    else:
        raise ValueError("command not found")


if __name__ == "__main__":
    main()
