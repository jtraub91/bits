"""
bits cli
"""
import argparse
import json
import os
import random
import sys
import time

import ecdsa
import toml

import bits.openssl
import bits.rpc
from bits import default_config
from bits import set_log_level
from bits.base58 import base58check_decode
from bits.bips.bip32 import parse_256
from bits.bips.bip32 import point
from bits.bips.bip32 import ser_p
from bits.bips.bip32 import to_master_key
from bits.bips.bip39 import generate_mnemonic_phrase
from bits.bips.bip39 import to_seed
from bits.p2p import Node
from bits.p2p import set_magic_start_bytes
from bits.rpc import rpc_method
from bits.script.constants import SIGHASH_ALL
from bits.script.utils import p2pk_script_pubkey
from bits.script.utils import p2pk_script_sig
from bits.script.utils import p2pkh_script_pubkey
from bits.script.utils import p2pkh_script_sig
from bits.tx import outpoint
from bits.tx import tx
from bits.tx import txin
from bits.tx import txout
from bits.utils import compressed_pubkey
from bits.utils import compute_point
from bits.utils import d_hash
from bits.utils import decode_key
from bits.utils import ensure_sig_low_s
from bits.utils import point
from bits.utils import pubkey
from bits.utils import pubkey_from_pem
from bits.utils import pubkey_hash
from bits.utils import s_hash
from bits.utils import to_bitcoin_address
from bits.wallet import HD
from bits.wallet import Wallet


def main():
    bitsconfig = default_config()
    bitsconfig.update(toml.load(".bitsconfig.toml"))

    parser = argparse.ArgumentParser(
        prog="bits",
    )
    parser.add_argument(
        "-N",
        "--network",
        type=str,
        dest="network",
        choices=["mainnet", "testnet"],
        help="network, e.g. 'mainnet' or 'testnet'",
    )
    parser.add_argument(
        "-L",
        "--log-level",
        dest="log_level",
        type=str,
        help="log level, e.g. 'info', 'debug', 'warning', etc.",
    )

    sub_parser = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="<command>",
        description="Use bits <command> -h for help on each command",
    )

    wallet_parser = sub_parser.add_parser("wallet", help="wallet interface")
    wallet_sub_parser = wallet_parser.add_subparsers(dest="wallet_command")

    wallet_create_parser = wallet_sub_parser.add_parser(
        "create", help="create a new wallet"
    )
    wallet_create_parser.add_argument("-n", "--wallet-name", help="name of wallet")
    wallet_create_parser.add_argument(
        "-T",
        "--wallet-type",
        choices=["hd", "jbok"],
        help="type of wallet",
    )
    wallet_create_parser.add_argument(
        "-S",
        "--strength",
        type=int,
        default=256,
        choices=[128, 160, 192, 224, 256],
        help="entropy strenghth (in bits) for mnemonic generation",
    )

    wallet_load_parser = wallet_sub_parser.add_parser("load", help="load wallet")
    wallet_getbalance_parser = wallet_sub_parser.add_parser(
        "getbalance", help="get wallet balance"
    )
    wallet_listkeys_parser = wallet_sub_parser.add_parser(
        "listkeys", help="list wallet keys"
    )
    wallet_listaddrs_parser = wallet_sub_parser.add_parser(
        "listaddrs", help="list wallet addresses"
    )
    wallet_send_parser = wallet_sub_parser.add_parser("send", help="send wallet funds")
    wallet_receive_parser = wallet_sub_parser.add_parser(
        "receive", help="receive funds to wallet"
    )
    # wallet_tx_parser = wallet_sub_parser.add_parser("tx", help="interface with raw transactions")
    # wallet_rx_parser = wallet_sub_parser.add_parser("rx", help="troubleshoot")
    # wallet_sub_parser.add_parser("tx", help="")
    # ...
    # wallet_parser.add_argument("command", type=str, help="create, load, getbalance, listkeys, listaddrs, tx, rx, send, receive")

    p2p_parser = sub_parser.add_parser("p2p", help="start p2p node")
    p2p_parser.add_argument(
        "--seeds", type=str, help="comma separated list of seed nodes"
    )

    genkey_parser = sub_parser.add_parser(
        "genkey",
        description="Generate bitcoin private key",
        help="generate bitcoin private key",
    )
    genkey_parser.add_argument("-out", "--out", help="secret key output file")
    # genkey_parser.add_argument("--out-format", default="pem", choices=["pem", "der"], help="key output format")

    pubkey_parser = sub_parser.add_parser(
        "pubkey",
        description="Output public key",
        help="get public key from private / public key",
    )
    pubkey_parser.add_argument(
        "-in", "--in", dest="in_file", type=str, help="private key input file"
    )
    pubkey_parser.add_argument("-out", "--out", help="public key output file")
    pubkey_parser.add_argument(
        "-X",
        "--compressed",
        action="store_true",
        default=False,
        help="compressed public key",
    )
    pubkey_parser.add_argument(
        "-f",
        "--out-format",
        default="pem",
        choices=["pem", "hex"],
        help="public key output format",
    )

    addr_parser = sub_parser.add_parser(
        "addr",
        description="Output standard address types",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    addr_parser.add_argument(
        "-in", "--in", dest="in_file", help="public key input file"
    )
    addr_parser.add_argument(
        "-T",
        "--type",
        default="p2pkh",
        choices=["p2pkh", "p2sh", "bech32"],
        help="address invoice type",
    )
    # TODO: addr command should not have -X compressed flag, should conform to what original pubkey was
    # and perhaps refactor to only allow -in <pubkey> (see bits.utils.pubkey_from_pem)
    # and also perhaps refactor/develop minimal der decoder to remove ecdsa dependency
    addr_parser.add_argument(
        "-X",
        "--compressed",
        action="store_true",
        default=False,
        help="compressed public key",
    )

    tx_parser = sub_parser.add_parser(
        "tx",
        help="create transactions",
        description="create transactions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    tx_parser.add_argument(
        "-txin",
        "--txin",
        dest="txins",
        type=json.loads,
        action="append",
        default=[],
        help="Transaction input data provided as a dictionary with the following keys: txid, vout, scriptSig. Use scriptPubKey as scriptSig if generating the pre-signature transaction.",
    )
    tx_parser.add_argument(
        "-txout",
        "--txout",
        dest="txouts",
        type=json.loads,
        action="append",
        default=[],
        help="Transaction output data provided as a dictionary with the following keys: satoshis, scriptPubKey",
    )
    # tx_parser.add_argument("-T", "--type", choices=["p2pk, p2pkh, p2sh, p2wpkh"], default="", help="transaction type")

    script_pubkey_parser = sub_parser.add_parser(
        "scriptpubkey", help="create bitcoin pubkey scripts"
    )
    script_pubkey_parser.add_argument("addr", help="create scriptPubKey from addr")
    script_pubkey_parser.add_argument(
        "-type",
        "--type",
        default="p2pkh",
        choices=["p2pk", "p2pkh"],
        help="scriptPubKey type",
    )

    script_sig_parser = sub_parser.add_parser("scriptsig", help="create scriptSig")
    script_sig_parser.add_argument(
        "-tx", "--tx", type=str, help="raw transaction (hex)"
    )
    script_sig_parser.add_argument(
        "-privkey",
        "--privkey",
        metavar="file",
        type=str,
        help="private key filename to use for signing (pem)",
    )
    script_sig_parser.add_argument(
        "-X",
        "--compressed-pubkey",
        action="store_true",
        default=False,
        help="use if scriptSig is for P2PKH scriptPubKey with compressed pubkey",
    )
    script_sig_parser.add_argument(
        "--type",
        default="p2pkh",
        choices=["p2pkh", "p2pk", "p2sh", "p2wpkh"],
        help="scriptSig type",
    )
    script_sig_parser.add_argument(
        "-sigdep",
        "--sigdep",
        choices=["openssl", "python-ecdsa", "native"],
        default="openssl",
        help="dependency to use for signing",
    )

    rpc_parser = sub_parser.add_parser(
        "rpc", help="rpc interface", description="Send command to RPC node"
    )
    rpc_parser.add_argument("rpc_command", help="rpc command")
    rpc_parser.add_argument("params", nargs="*", help="params for rpc_command")
    rpc_parser.add_argument("-rpcurl", "--rpcurl", dest="rpc_url", help="rpc url")
    rpc_parser.add_argument("-rpcuser", "--rpcuser", dest="rpc_user", help="rpc user")
    rpc_parser.add_argument(
        "-rpcpassword", "--rpcpassword", dest="rpc_password", help="rpc password"
    )

    args = parser.parse_args()
    if args.network:
        bitsconfig.update({"network": args.network})
    if args.log_level:
        bitsconfig.update({"loglevel": args.log_level})

    set_log_level(bitsconfig["loglevel"])
    set_magic_start_bytes(bitsconfig["network"])

    if not args.command:
        parser.print_help()
    elif args.command == "wallet":
        if not args.wallet_command:
            wallet_parser.print_help()
        elif args.wallet_command == "create":
            if not args.wallet_type:
                wallet_type = input(
                    "What type of wallet do you want to create? (JBOK or HD): "
                )
            else:
                wallet_type = args.wallet_type
            wallet_type = wallet_type.lower()
            if wallet_type not in ["jbok", "hd"]:
                print(f"choice not recognized: {wallet_type}")
                exit()
            if not args.wallet_name:
                wallet_name = input("Specify wallet name: ")
            else:
                wallet_name = args.wallet_name
            if os.path.exists(f".bits/wallets/{wallet_type}/{wallet_name}"):
                print(
                    f"'{wallet_name}' {wallet_type} wallet already exists. Exiting... "
                )
                exit()
            else:
                if wallet_type == "jbok":
                    wallet_dir = f".bits/wallets/{wallet_type}/{wallet_name}"
                    os.makedirs(wallet_dir)

                    secret_pem = (
                        f".bits/wallets/{wallet_type}/{wallet_name}/secret0.pem"
                    )
                    public_pem = (
                        f".bits/wallets/{wallet_type}/{wallet_name}/public0.pem"
                    )

                    bits.openssl.genkey(out=secret_pem)
                    print(f"Secret key saved to {secret_pem}")

                    bits.openssl.pubkey_pem(
                        in_=secret_pem, out=public_pem, compressed=True
                    )
                    print(f"Public key saved to {public_pem}")
                else:
                    # wallet_type == "hd"
                    wallet_dir = f".bits/wallets/{wallet_type}/{wallet_name}"
                    os.makedirs(wallet_dir)
                    filepath = os.path.join(wallet_dir, "mnemonic.txt")
                    with open(filepath, "w") as file_:
                        file_.write(generate_mnemonic_phrase(strength=args.strength))
                    print(f"Mnemonic phrase saved to {filepath}")
        elif args.wallet_command == "load":
            # wallet = Wallet()
            # wallet.load()
            raise NotImplementedError
        elif args.wallet_command == "":
            pass
        else:
            raise ValueError("wallet command not found")
    elif args.command == "p2p":
        # bits --network testnet p2p start --seeds "host1:port1,host2:port2"
        if not args.seeds:
            raise NotImplementedError
            p2p_node = Node()
        p2p_node = Node(seeds=args.seeds.split(","))
        p2p_node.start()
    elif args.command == "genkey":
        if not args.out:
            print(bits.openssl.genkey().decode("utf8"))
        else:
            bits.openssl.genkey(args.out)
    elif args.command == "pubkey":
        if args.out_format == "hex":
            if args.in_file:
                with open(args.in_file, "rb") as file_:
                    in_bytes = file_.read()
            else:
                in_bytes = "".join([line for line in sys.stdin]).encode("utf8")
            key = decode_key(in_bytes)
            if len(key) == 2:
                key = key[1]
            if args.compressed:
                key = compressed_pubkey(key)
            return key.hex()
        # else out_format == "pem"
        # this mode only takes private key pem, not public
        # TODO: add in_format, in addition to out_format, currently only pem
        # TODO: remove openssl dep, implement pem/der encoder
        print(
            bits.openssl.pubkey_pem(
                args.in_file, args.out, compressed=args.compressed
            ).decode("utf8")
        )
    elif args.command == "addr":
        if not args.in_file:
            in_bytes = "".join([line for line in sys.stdin]).encode("utf8")
        else:
            with open(args.in_file, "rb") as file_:
                in_bytes = file_.read()
        pk = pubkey_from_pem(in_bytes)
        if args.compressed:
            pk = compressed_pubkey(pk)
        return to_bitcoin_address(
            pk, addr_type=args.type, network=bitsconfig["network"]
        )
    elif args.command == "tx":
        txins = []
        for txin_dict in args.txins:
            # internal byte order
            txid_ = bytearray.fromhex(txin_dict["txid"])
            txid_.reverse()
            txid_ = bytes(txid_)
            # use script pub key as script sig for signing
            script_sig = bytes.fromhex(txin_dict["scriptSig"])
            txin_ = txin(outpoint(bytes(txid_), txin_dict["vout"]), script_sig)
            txins.append(txin_)
        txouts = [
            txout(txout_dict["satoshis"], bytes.fromhex(txout_dict["scriptPubKey"]))
            for txout_dict in args.txouts
        ]
        tx_ = tx(txins, txouts)
        return tx_.hex()
    elif args.command == "scriptpubkey":
        if args.type == "p2pkh":
            decoded = base58check_decode(args.addr.encode("ascii"))
            version = decoded[0:1]
            payload = decoded[1:]
            return p2pkh_script_pubkey(payload).hex()
        elif args.type == "p2pk":
            return p2pk_script_pubkey(bytes.fromhex(args.addr)).hex()
        else:
            raise NotImplementedError
    elif args.command == "scriptsig":
        if args.sigdep == "openssl":
            if args.tx:
                tx_ = bytes.fromhex(args.tx)
                # single hash since bits.openssl.sign does another one
                sig_data = s_hash(tx_ + SIGHASH_ALL.to_bytes(4, "little"))
                # save sig_data as tmp file;
                if not os.path.exists(".bits/tmp"):
                    os.makedirs(".bits/tmp")
                tmp_filename = f".bits/tmp/{int(1000 * time.time())}.sigdata"
                with open(tmp_filename, "wb") as tmp_file:
                    tmp_file.write(sig_data)
                sig = bits.openssl.sign(args.privkey, files=[tmp_filename])
                sig = ensure_sig_low_s(sig)
                os.remove(tmp_filename)
            else:
                # read line from stdin
                # transform hex to bytes, take single hash, send to openssl
                # TODO: support multiple lines
                for line in sys.stdin:
                    stdin_bytes = bytes.fromhex(line)
                    stdin_bytes = s_hash(stdin_bytes)
                    sig = bits.openssl.sign(args.privkey, stdin=stdin_bytes)
                    sig = ensure_sig_low_s(sig)
            with open(args.privkey, "rb") as privkey_file:
                privkey_bytes = privkey_file.read()
                pubkey_ = pubkey_from_pem(privkey_bytes)
            if args.compressed_pubkey:
                pubkey_ = compressed_pubkey(pubkey_)
            if args.type == "p2pkh":
                return p2pkh_script_sig(sig, pubkey_).hex()
            elif args.type == "p2pk":
                return p2pk_script_sig(sig).hex()
            else:
                raise NotImplementedError(args.type)
        elif args.sigdep == "python-ecdsa":
            if args.tx:
                tx_ = bytes.fromhex(args.tx)
            else:
                tx_ = bytes.fromhex("".join([line for line in sys.stdin]))
            sig_data = d_hash(tx_ + SIGHASH_ALL.to_bytes(4, "little"))
            tmp_filename = f".bits/tmp/{int(1000 * time.time())}.sigdata"
            with open(tmp_filename, "wb") as tmp_file:
                tmp_file.write(sig_data)
            with open(args.privkey, "rb") as privkey_file:
                privkey_pem = privkey_file.read()
                privkey = decode_key(privkey_pem)[0]
                pubkey_ = pubkey(
                    *compute_point(privkey),
                    compressed=args.compressed_pubkey,
                )
            signing_key = ecdsa.SigningKey.from_pem(privkey_pem)
            sig = signing_key.sign_digest(sig_data, sigencode=ecdsa.util.sigencode_der)
            sig = ensure_sig_low_s(sig)
            assert signing_key.verifying_key.verify_digest(
                sig, sig_data, sigdecode=ecdsa.util.sigdecode_der
            )
            tmp_filename_2 = os.path.splitext(tmp_filename)[0] + ".sig"
            with open(tmp_filename_2, "wb") as tmp_file:
                tmp_file.write(sig)
            if args.type == "p2pkh":
                return p2pkh_script_sig(sig, pubkey_).hex()
            elif args.type == "p2pk":
                return p2pk_script_sig(sig).hex()
            else:
                raise NotImplementedError(args.type)
        elif args.sigdep == "native":
            raise NotImplementedError
        else:
            raise ValueError("sigdep not supported")
    elif args.command == "rpc":
        if args.rpc_url:
            bitsconfig.update({"rpcurl": args.rpc_url})
        if args.rpc_user:
            bitsconfig.update({"rpcuser": args.rpc_user})
        if args.rpc_password:
            bitsconfig.update({"rpcpassword": args.rpc_password})

        print(
            rpc_method(
                args.rpc_command,
                *args.params,
                rpc_url=bitsconfig["rpcurl"],
                rpc_user=bitsconfig["rpcuser"],
                rpc_password=bitsconfig["rpcpassword"],
            )
        )
    else:
        raise ValueError("command not recognized")


if __name__ == "__main__":
    main()
