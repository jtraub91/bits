"""
bits cli
"""
import argparse
import functools
import json
import os
import secrets
import stat
import sys
import time

import bits.base58
import bits.openssl
import bits.rpc
import bits.script
from bits.base58 import base58check_decode
from bits.bips.bip173 import segwit_addr
from bits.bips.bip39 import calculate_mnemonic_phrase
from bits.blockchain import genesis_block
from bits.ecmath import SECP256K1_N
from bits.p2p import Node
from bits.p2p import set_magic_start_bytes
from bits.rpc import rpc_method
from bits.tx import outpoint
from bits.tx import send_tx
from bits.tx import tx
from bits.tx import txin
from bits.tx import txout
from bits.utils import compressed_pubkey
from bits.utils import compute_point
from bits.utils import ensure_sig_low_s
from bits.utils import hash256
from bits.utils import pem_decode_key
from bits.utils import pem_encode_key
from bits.utils import pubkey
from bits.utils import pubkey_from_pem
from bits.utils import pubkey_hash
from bits.utils import ripemd160
from bits.utils import s_hash
from bits.utils import script_hash
from bits.utils import sha256
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
            return "keyboard interrupt."

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
        choices=["mainnet", "testnet", "regtest"],
        help="network, e.g. 'mainnet' or 'testnet'",
    )
    parser.add_argument(
        "-L",
        "--log-level",
        dest="log_level",
        type=str,
        help="log level, e.g. 'info', 'debug', 'warning', etc.",
    )


def add_input_arguments(
    parser: argparse.ArgumentParser,
    in_file_help: str = "input data file",
    include_pem: bool = False,
):
    parser.add_argument(
        "--in-file",
        type=argparse.FileType("rb")
        if bits.bitsconfig["input_format"] == "raw"
        else argparse.FileType("r"),
        help=in_file_help,
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-1",
        dest="input_format_raw",
        action="store_true",
        help="input data file format - raw binary",
    )
    input_group.add_argument(
        "-1b",
        dest="input_format_bin",
        action="store_true",
        help="input data file format - binary string",
    )
    input_group.add_argument(
        "-1x",
        dest="input_format_hex",
        action="store_true",
        help="input data file format - hexadecimal string",
    )
    if include_pem:
        input_group.add_argument(
            "-1pem",
            dest="input_format_pem",
            action="store_true",
            help="input data file format - pem",
        )


def add_output_arguments(
    parser: argparse.ArgumentParser, out_file_help: str = "output data file"
):
    parser.add_argument(
        "--out-file",
        type=argparse.FileType("wb")
        if bits.bitsconfig["output_format"] == "raw"
        else argparse.FileType("w"),
        help="output data file",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-0",
        dest="output_format_raw",
        action="store_true",
        help="output data file format - raw binary",
    )
    output_group.add_argument(
        "-0b",
        dest="output_format_bin",
        action="store_true",
        help="output data file format - binary string",
    )
    output_group.add_argument(
        "-0x",
        dest="output_format_hex",
        action="store_true",
        help="output data file format - hexadecimal string",
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

    # TODO: support pem input / output for key & pub
    key_parser = sub_parser.add_parser(
        "key",
        help="generate Bitcoin secret key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common_arguments(key_parser)
    add_output_arguments(key_parser)

    pubkey_parser = sub_parser.add_parser(
        "pubkey", help="pubkey from secret (or pubkey)"
    )
    pubkey_parser.add_argument("-X", "--compressed", action="store_true", default=False)
    add_common_arguments(pubkey_parser)
    add_input_arguments(pubkey_parser, include_pem=True)
    add_output_arguments(pubkey_parser)

    wif_parser = sub_parser.add_parser("wif", help="encode or decode WIF key")
    wif_parser.add_argument("--decode", action="store_true", default=False)
    wif_parser.add_argument(
        "-X",
        "--compressed-pubkey",
        default=False,
        action="store_true",
        help="wif key corresponds to compressed pubkey",
    )
    add_common_arguments(wif_parser)
    add_input_arguments(wif_parser)
    add_output_arguments(wif_parser)

    wif_decode_parser = sub_parser.add_parser("wif_decode")
    add_input_arguments(wif_decode_parser)

    addr_parser = sub_parser.add_parser(
        "addr",
        help="base58check and segwit Bitcoin addresses",
        description="Output standard address types from scripthash or pubkeyhash",
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
        ignored when --witness-version is present
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

    script_parser = sub_parser.add_parser(
        "script",
        help="create generic scripts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Create generic Scripts. script_args are either OP_* or data

Standard transaction scripts:
    P2PK:
        scriptPubkey: <pubkey> OP_CHECKSIG
        scriptSig: <sig>
    P2PKH:
        scriptPubkey: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        scriptSig: <sig> <pubkey>
    P2SH:
        scriptPubkey: OP_HASH160 <scripthash> OP_EQUAL
        scriptSig: <sig> ... <redeemScript>
    Multisig:
        scriptPubkey: OP_M <pubkey> ... OP_N OP_CHECKMULTISIG
        scriptSig: OP_0 <sig> ...
    Null:
        scriptPubkey: OP_RETURN <data>
        """,
    )
    script_parser.add_argument("script_args", nargs="+", help="script code")
    add_output_arguments(script_parser)

    sig_parser = sub_parser.add_parser(
        "sig", help="create bitcoin signature, i.e. HASH256(msg + SIGHASH_FLAG)"
    )
    sig_parser.add_argument(
        "msg", help="message data to hash and sign", type=bytes.fromhex
    )
    sig_parser.add_argument(
        "--sighash",
        default="all",
        choices=["all", "none", "single"],
        help="""
        Sighash type to append to msg before HASH256
        """,
    )
    sig_parser.add_argument(
        "--anyone-can-pay",
        default=False,
        action="store_true",
        help="If present, ORs --sighash flag with SIGHASH_ANYONECANPAY",
    )
    sig_parser.add_argument(
        "--witness-version", type=int, help="witness version, if segwit signature"
    )
    add_input_arguments(sig_parser, in_file_help="private key input")
    add_output_arguments(sig_parser, out_file_help="signature output")

    sigverify_parser = sub_parser.add_parser("sigverify", help="verify sigs")
    sigverify_parser.add_argument("sig", type=bytes.fromhex)
    sigverify_parser.add_argument("msg", type=bytes.fromhex)
    sigverify_parser.add_argument(
        "--sighash",
        default="all",
        choices=["all", "none", "single"],
        help="""
        Sighash type to append to msg before HASH256
        """,
    )
    sigverify_parser.add_argument(
        "--anyone-can-pay",
        default=False,
        action="store_true",
        help="If present, ORs --sighash flag with SIGHASH_ANYONECANPAY",
    )
    add_input_arguments(sigverify_parser, in_file_help="public key input")

    ripemd160_parser = sub_parser.add_parser("ripemd160", help="ripemd160(data)")
    add_input_arguments(ripemd160_parser)
    add_output_arguments(ripemd160_parser)

    sha256_parser = sub_parser.add_parser("sha256", help="sha256(data)")
    add_input_arguments(sha256_parser)
    add_output_arguments(sha256_parser)

    hash160_parser = sub_parser.add_parser(
        "hash160", help="HASH160(data), i.e. ripemd160(sha256(data))"
    )
    add_input_arguments(hash160_parser)
    add_output_arguments(hash160_parser)

    hash256_parser = sub_parser.add_parser(
        "hash256", help="HASH256(data), i.e. sha256(sha256(data))"
    )
    add_input_arguments(hash256_parser)
    add_output_arguments(hash256_parser)

    base58_parser = sub_parser.add_parser("base58", help="base58 encoding / decoding")
    base58_parser.add_argument(
        "--decode", default=False, action="store_true", help="decode input"
    )
    base58_parser.add_argument(
        "--check", default=False, action="store_true", help="base58check encode/decode"
    )
    add_input_arguments(base58_parser)
    add_output_arguments(base58_parser)

    bech32_parser = sub_parser.add_parser("bech32", help="todo")

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

    createsendtx_parser = sub_parser.add_parser(
        "createsendtx", help="Create tx for sending funds from addr to addr"
    )
    createsendtx_parser.add_argument("from_", type=os.fsencode)
    createsendtx_parser.add_argument("to_", type=os.fsencode)
    createsendtx_parser.add_argument(
        "--scriptsig",
        type=bytes.fromhex,
        help="""
        Unlocking script for from_ addr. 
        Leave off for pre-signature P2PK and P2PKH.
        Fill with redeemScript for pre-signature non-segwit P2SH
        """,
    )
    createsendtx_parser.add_argument(
        "--miner-fee", type=int, default=1000, help="satoshis to include as miner fee"
    )
    add_output_arguments(createsendtx_parser)

    p2p_parser = sub_parser.add_parser("p2p", help="start p2p node")
    p2p_parser.add_argument(
        "--seeds", type=str, help="comma separated list of seed nodes"
    )

    blockchain_parser = sub_parser.add_parser("blockchain", help="blockchain utils")
    blockchain_parser.add_argument("blockheight", type=int, help="block height")
    add_output_arguments(blockchain_parser)

    if bits.bitsconfig["network"] == "regtest":
        generate_parser = sub_parser.add_parser(
            "generate",
            help="Generate blocks with coinbase tx with block reward sent to new p2pkh addr",
        )
        generate_parser.add_argument(
            "count", type=int, help="Number of blocks/keys/addrs to generate"
        )

        mineblock_parser = sub_parser.add_parser("mineblock")

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
    elif args.command == "pubkey":
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
    elif args.command == "wif":
        privkey_ = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        wif = bits.utils.wif_encode(
            privkey_,
            compressed_pubkey=args.compressed_pubkey,
            network=bits.bitsconfig["network"],
        )
        bits.print_bytes(wif + os.linesep.encode("utf8"), output_format="raw")
    elif args.command == "wif_decode":
        wif_ = bits.read_bytes(args.in_file, input_format="raw")
        decoded = bits.utils.wif_decode(wif_)
        version, key, compressed_pk = decoded[0], decoded[1], decoded[2]
        print(
            json.dumps(
                {
                    "version": version.hex(),
                    "key": key.hex(),
                    "compressed_pubkey": compressed_pk,
                }
            )
        )
    elif args.command == "ripemd160":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.print_bytes(
            ripemd160(data), output_format=bits.bitsconfig["output_format"]
        )
    elif args.command == "sha256":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.print_bytes(sha256(data), output_format=bits.bitsconfig["output_format"])
    elif args.command == "hash160":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.print_bytes(
            pubkey_hash(data), output_format=bits.bitsconfig["output_format"]
        )
    elif args.command == "hash256":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.print_bytes(hash256(data), output_format=bits.bitsconfig["output_format"])
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
            bits.script.utils.script(args.script_args),
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.command == "sig":
        key = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        sighash_flag = getattr(bits.script.constants, f"SIGHASH_{args.sighash.upper()}")
        if args.anyone_can_pay:
            sighash_flag |= bits.script.constants.SIGHASH_ANYONECANPAY
        sig = bits.utils.sig(key, args.msg, sighash_flag=sighash_flag)
        bits.print_bytes(sig, output_format=bits.bitsconfig["output_format"])
    elif args.command == "sigverify":
        pubkey_ = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        print(bits.utils.sig_verify(args.sig, pubkey_, args.msg))
    elif args.command == "createsendtx":
        tx_ = send_tx(
            args.from_,
            args.to_,
            scriptsig=args.scriptsig,
            miner_fee=args.miner_fee,
        )
        bits.print_bytes(tx_, output_format=bits.bitsconfig["output_format"])
    elif args.command == "generate":
        from bits.integrations import generate_funded_keys

        funded_keys = {
            key.decode("utf8"): addr.decode("utf8")
            for key, addr in generate_funded_keys(args.count, network="regtest")
        }
        print(json.dumps(funded_keys, indent=2))
    elif args.command == "mineblock":
        from bits.integrations import mine_block

        mine_block(network="regtest")
    elif args.command == "p2p":
        # bits --network testnet p2p start --seeds "host1:port1,host2:port2"
        if not args.seeds:
            raise NotImplementedError
            p2p_node = Node()
        p2p_node = Node(seeds=args.seeds.split(","))
        p2p_node.start()
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
