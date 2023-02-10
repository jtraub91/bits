"""
bits cli
"""
import argparse
import functools
import json
import os
import secrets
import sys
import time

import bits.openssl
import bits.rpc
from bits.base58 import base58check_decode
from bits.bips.bip173 import segwit_addr
from bits.bips.bip39 import calculate_mnemonic_phrase
from bits.blockchain import genesis_block
from bits.ecmath import SECP256K1_N
from bits.p2p import Node
from bits.p2p import set_magic_start_bytes
from bits.rpc import rpc_method
from bits.script.constants import SIGHASH_ALL
from bits.script.utils import multisig_script_pubkey
from bits.script.utils import p2pk_script_pubkey
from bits.script.utils import p2pk_script_sig
from bits.script.utils import p2pkh_script_pubkey
from bits.script.utils import p2pkh_script_sig
from bits.script.utils import p2sh_script_pubkey
from bits.script.utils import script
from bits.script.utils import scriptpubkey
from bits.tx import outpoint
from bits.tx import tx
from bits.tx import txin
from bits.tx import txout
from bits.utils import compressed_pubkey
from bits.utils import compute_point
from bits.utils import ensure_sig_low_s
from bits.utils import pem_decode_key
from bits.utils import pem_encode_key
from bits.utils import pubkey
from bits.utils import pubkey_from_pem
from bits.utils import pubkey_hash
from bits.utils import s_hash
from bits.utils import script_hash
from bits.utils import to_bitcoin_address


def catch_exception(fun):
    @functools.wraps(fun)
    def wrapper():
        try:
            return fun()
        except Exception as err:
            if bits.bitsconfig.get("debug"):
                raise err
            return err
        except KeyboardInterrupt:
            return "keyboard interrupt. exiting..."

    return wrapper


def update_config(args):
    if args.network:
        bits.bitsconfig.update({"network": args.network})
    if args.log_level:
        bits.bitsconfig.update({"loglevel": args.log_level})

    if args.output_format_raw:
        bits.bitsconfig.update({"output_format": "raw"})
    if args.output_format_bin:
        bits.bitsconfig.update({"output_format": "bin"})
    if args.output_format_hex:
        bits.bitsconfig.update({"output_format": "hex"})
    if args.input_format_raw:
        bits.bitsconfig.update({"input_format": "raw"})
    if args.input_format_bin:
        bits.bitsconfig.update({"input_format": "bin"})
    if args.input_format_hex:
        bits.bitsconfig.update({"input_format": "hex"})


def add_common_arguments(parser: argparse.ArgumentParser):
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


def add_input_arguments(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--in-file",
        type=argparse.FileType("rb")
        if bits.bitsconfig["input_format"] == "raw"
        else argparse.FileType("r"),
        help="input data file, if applicable",
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-1",
        dest="input_format_raw",
        action="store_true",
        help="input format raw binary",
    )
    input_group.add_argument(
        "-1b",
        dest="input_format_bin",
        action="store_true",
        help="input format binary string",
    )
    input_group.add_argument(
        "-1x",
        dest="input_format_hex",
        action="store_true",
        help="input format hexadecimal string",
    )


def add_output_arguments(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--out-file",
        type=argparse.FileType("wb")
        if bits.bitsconfig["output_format"] == "raw"
        else argparse.FileType("w"),
        help="output data to file, if applicable",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-0",
        dest="output_format_raw",
        action="store_true",
        help="output format raw binary",
    )
    output_group.add_argument(
        "-0b",
        dest="output_format_bin",
        action="store_true",
        help="output format binary string",
    )
    output_group.add_argument(
        "-0x",
        dest="output_format_hex",
        action="store_true",
        help="output format hexadecimal string",
    )


@catch_exception
def main():
    bits_desc = """
    The `bits` command (with no sub-command) accepts input and transparently writes 
    output, in either raw binary, binary string, or hex string format. The format of the
    input and output can be specified independently using the following command options,
    making it able to be used as a converter between these formats.
    """
    parser = argparse.ArgumentParser(prog="bits", description=bits_desc)
    add_common_arguments(parser)
    add_input_arguments(parser)
    add_output_arguments(parser)

    sub_parser = parser.add_subparsers(
        dest="command",
        metavar="<command>",
        description="Use bits <command> -h for help on each command",
    )

    key_parser = sub_parser.add_parser("key", help="generate Bitcoin secret key")
    add_common_arguments(key_parser)
    add_output_arguments(key_parser)

    pub_parser = sub_parser.add_parser("pub", help="pubkey from secret (or pubkey)")
    pub_parser.add_argument("-X", "--compressed", action="store_true", default=False)
    add_common_arguments(pub_parser)
    add_input_arguments(pub_parser)
    add_output_arguments(pub_parser)

    script_parser = sub_parser.add_parser("script", help="create generic scripts")
    script_parser.add_argument("script_args", nargs="+", help="script code")
    add_output_arguments(script_parser)

    # TODO: sig_parser

    p2p_parser = sub_parser.add_parser("p2p", help="start p2p node")
    p2p_parser.add_argument(
        "--seeds", type=str, help="comma separated list of seed nodes"
    )
    scripthash_parser = sub_parser.add_parser(
        "scripthash", help="ripemd160(redeem_script)"
    )
    add_input_arguments(scripthash_parser)
    add_output_arguments(scripthash_parser)

    pubkeyhash_parser = sub_parser.add_parser(
        "pubkeyhash", help="ripemd160(sha256(pubkey))"
    )
    pubkeyhash_parser.add_argument(
        "--pem",
        action="store_true",
        default=False,
        help="use pem encoded private/public input file",
    )
    add_input_arguments(pubkeyhash_parser)
    add_output_arguments(pubkeyhash_parser)

    addr_parser = sub_parser.add_parser(
        "addr",
        description="Output standard address types from scripthash or pubkeyhash",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    addr_parser.add_argument(
        "-T",
        "--type",
        default="p2pkh",
        choices=[
            "p2pkh",
            "p2sh",
        ],
        help="""
        address invoice type. 
        when combined with --witness-version, will result in p2wpkh and p2wsh, accordingly
        """,
    )
    addr_parser.add_argument(
        "--witness-version",
        type=int,
        help="witness version for native segwit addresses",
        choices=range(17),
    )
    add_common_arguments(addr_parser)
    add_input_arguments(addr_parser)

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
        help="""
        Transaction input data provided as a dictionary with the following keys: txid, vout, scriptSig.
        Use scriptPubKey as scriptSig if generating the pre-signature transaction.
        """,
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
    # # BIP 68 transaction version 2+
    # # https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
    # tx_parser.add_argument("-v", "--version", type=int, default=1, help="transaction version")

    script_pubkey_parser = sub_parser.add_parser(
        "scriptpubkey", help="create scriptPubKey of various types. "
    )
    script_pubkey_parser.add_argument(
        "data", nargs="*", help="data per scriptPubKey type"
    )
    script_pubkey_parser.add_argument(
        "-type",
        "--type",
        choices=[
            "p2pk",
            "p2pkh",
            "multisig",
            "null",
            "p2sh",
            # "p2sh-multisig",
            # "p2sh-p2wpkh",
            # "p2sh-p2wsh",
            "p2wpkh",
            "p2wsh",
        ],
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
        choices=[
            "p2pk",
            "p2pkh",
            "multisig",
            "p2sh",
            "p2wpkh",
            "p2wsh",
        ],
        help="scriptSig type",
    )
    script_sig_parser.add_argument(
        "-sigdep",
        "--sigdep",
        choices=["openssl", "native"],
        default="openssl",
        help="dependency to use for signing",
    )

    scan_parser = sub_parser.add_parser("scan", help="scan utxoset for addr")
    scan_parser.add_argument("addr")

    sweep_parser = sub_parser.add_parser(
        "sweep",
        help="convencience utility for sending (all or a fraction) currency associated with addr",
    )
    # change addr
    # miner fee
    sweep_parser.add_argument("addr")
    sweep_parser.add_argument("--miner-fee")
    sweep_parser.add_argument("--fraction", default=1)
    sweep_parser.add_argument("--change-addr")

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

    mnemonic_parser = sub_parser.add_parser("mnemonic", help="mnemonic utils")
    mnemonic_parser.add_argument(
        "entropy",
        nargs="?",
        type=argparse.FileType("rb"),
        # ^ doesn't work for "-" on python < 3.9
        # https://github.com/python/cpython/issues/58364
    )
    mnemonic_parser.add_argument(
        "--generate",
        action="store_true",
    )
    mnemonic_parser.add_argument(
        "-S",
        "--strength",
        type=int,
        default=256,
        choices=[128, 160, 192, 224, 256],
        help="entropy strenghth (in bits) for mnemonic generation",
    )
    mnemonic_parser.add_argument("--show-details", action="store_true")
    mnemonic_parser.add_argument("--to-master-key")
    mnemonic_parser.add_argument(
        "--to-seed",
        action="store_true",
    )
    mnemonic_parser.add_argument("--to-entropy")

    blockchain_parser = sub_parser.add_parser("blockchain", help="blockchain utils")
    blockchain_parser.add_argument("blockheight", type=int, help="block height")

    args = parser.parse_args()
    update_config(args)

    bits.set_log_level(bits.bitsconfig["loglevel"])
    set_magic_start_bytes(bits.bitsconfig["network"])

    if not args.command:
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.print_bytes(data, output_format=bits.bitsconfig["output_format"])
    elif args.command == "key":
        # generate Bitcoin secret key
        k = secrets.randbelow(SECP256K1_N)
        bits.print_bytes(
            k.to_bytes(32, "big"), output_format=bits.bitsconfig["output_format"]
        )
    elif args.command == "pub":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        if len(data) == 32:
            # privkey
            x, y = compute_point(data)
            pk = pubkey(x, y, compressed=args.compressed)
        elif len(data) == 33 or len(data) == 65:
            # pubkey
            pk = compressed_pubkey(data) if args.compressed else data
        else:
            raise ValueError("data not recognized as private or public key")
        bits.print_bytes(
            pk,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.command == "scripthash":
        redeem_script = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.print_bytes(
            script_hash(redeem_script), output_format=bits.bitsconfig["output_format"]
        )
    elif args.command == "pubkeyhash":
        if args.pem:
            pubkey_pem = bits.read_bytes(args.in_file, input_format="raw")
            pubkey_ = pem_decode_key(pubkey_pem)[-1]
        else:
            pubkey_ = bits.read_bytes(
                args.in_file, input_format=bits.bitsconfig["input_format"]
            )
        bits.print_bytes(
            pubkey_hash(pubkey_), output_format=bits.bitsconfig["output_format"]
        )
    elif args.command == "addr":
        payload = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        addr = to_bitcoin_address(
            payload,
            addr_type=args.type,
            witness_version=args.witness_version,
            network=bits.bitsconfig["network"],
        )
        bits.print_bytes(addr + os.linesep.encode("ascii"), output_format="raw")
    elif args.command == "p2p":
        # bits --network testnet p2p start --seeds "host1:port1,host2:port2"
        if not args.seeds:
            raise NotImplementedError
            p2p_node = Node()
        p2p_node = Node(seeds=args.seeds.split(","))
        p2p_node.start()
    elif args.command == "tx":
        txins = []
        for txin_dict in args.txins:
            # internal byte order
            txid_ = bytes.fromhex(txin_dict["txid"])[::-1]
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
    elif args.command == "script":
        bits.print_bytes(
            script(args.script_args), output_format=bits.bitsconfig["output_format"]
        )
    elif args.command == "scriptpubkey":
        bits.print_bytes(
            scriptpubkey(args.data), output_format=bits.bitsconfig["output_format"]
        )
        return
        if args.type == "p2pk":
            print(p2pk_script_pubkey(bytes.fromhex(args.data)).hex())
        elif args.type == "p2pkh" or args.type == "p2sh":
            decoded = base58check_decode(args.data.encode("ascii"))
            version = decoded[0:1]
            payload = decoded[1:]
            script_pubkey = (
                p2pkh_script_pubkey(payload)
                if args.type == "p2pkh"
                else p2sh_script_pubkey(payload)
            )
            print(script_pubkey.hex())
        elif args.type == "multisig":
            m = int(args.data[0])
            pubkeys = [bytes.fromhex(pk) for pk in args.data[1:]]
            print(multisig_script_pubkey(m, pubkeys).hex())
        elif args.type == "p2sh":
            decoded = base58check_decode(args.data.encode("ascii"))
            version = decoded[0:1]
            payload = decoded[1:]
            print(p2sh_script_pubkey(payload).hex())
        elif args.type == "p2sh-multisig":
            raise NotImplementedError
        elif args.type == "p2wpkh":
            raise NotImplementedError
        elif args.type == "p2wsh":
            raise NotImplementedError

        elif args.type == "p2sh-p2wpkh":
            raise NotImplementedError
        elif args.type == "p2sh-p2wsh":
            raise NotImplementedError
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
                tx_ = bits.read_bytes(
                    args.in_file, input_format=bits.bitsconfig["input_format"]
                )
                sigdata = s_hash(tx_ + SIGHASH_ALL.to_bytes(4, "little"))
                sig = bits.openssl.sign(args.privkey, stdin=sigdata)
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
        elif args.sigdep == "native":
            raise NotImplementedError
        else:
            raise ValueError("sigdep not supported")
    elif args.command == "scan":
        # scan utxo set for addr
        # for now use bitcoind via rpc
        # future: natively support scan internal blockchain
        result = rpc_method(
            "scantxoutset",
            "start",
            f'["addr({args.addr})"]',
            rpc_url=bits.bitsconfig["rpcurl"],
            rpc_user=bits.bitsconfig["rpcuser"],
            rpc_password=bits.bitsconfig["rpcpassword"],
        )
        print(json.dumps(result) if type(result) is dict else result)
        return
    elif args.command == "sweep":
        # sweep/send funds (or a fraction) to another address (+ change adress, if applicable)
        return
    elif args.command == "rpc":
        if args.rpc_url:
            bits.bitsconfig.update({"rpcurl": args.rpc_url})
        if args.rpc_user:
            bits.bitsconfig.update({"rpcuser": args.rpc_user})
        if args.rpc_password:
            bits.bitsconfig.update({"rpcpassword": args.rpc_password})

        result = rpc_method(
            args.rpc_command,
            *args.params,
            rpc_url=bits.bitsconfig["rpcurl"],
            rpc_user=bits.bitsconfig["rpcuser"],
            rpc_password=bits.bitsconfig["rpcpassword"],
        )
        print(json.dumps(result) if type(result) is dict else result)
    elif args.command == "mnemonic":
        if args.generate:
            # generate entropy
            entropy = secrets.token_bytes(args.strength // 8)
        elif args.entropy:
            # accept optional filename or -
            entropy = args.entropy.read()
        else:
            # read from stdin
            entropy = sys.stdin.buffer.read()
        print(calculate_mnemonic_phrase(entropy))
    elif args.command == "blockchain":
        if args.blockheight == 0:
            bits.print_bytes(
                genesis_block(), output_format=bits.bitsconfig["output_format"]
            )
        else:
            raise NotImplementedError
    else:
        raise ValueError("command not recognized")


if __name__ == "__main__":
    main()
