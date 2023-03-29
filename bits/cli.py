"""
bits cli
"""
import argparse
import functools
import json
import logging
import os
import secrets
import sys
from getpass import getpass

import bits.base58
import bits.blockchain
import bits.p2p
import bits.rpc
import bits.script
import bits.tx
import bits.wallet.hd
from bits.bips import bip173
from bits.bips import bip32
from bits.bips import bip39
from bits.integrations import mine_block

log = logging.getLogger(__name__)


class RawDescriptionDefaultsHelpFormatter(
    argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter
):
    pass


def catch_exception(fun):
    @functools.wraps(fun)
    def wrapper():
        try:
            return fun()
        except Exception as err:
            log.exception(err)
            return f"ERROR: {err}"
        except KeyboardInterrupt:
            return "keyboard interrupt."

    return wrapper


def update_config(args):
    if vars(args).get("network"):
        bits.bitsconfig.update({"network": args.network})
    if vars(args).get("log_level"):
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


def add_common_arguments(
    parser: argparse.ArgumentParser,
    include_network: bool = True,
    include_log_level: bool = True,
):
    if include_network:
        parser.add_argument(
            "--network",
            "-N",
            metavar="NETWORK",
            type=str,
            choices=["mainnet", "testnet", "regtest"],
            help="network, e.g. 'mainnet' or 'testnet'",
        )
    if include_log_level:
        parser.add_argument(
            "-L",
            "--log-level",
            type=str,
            help="log level, e.g. 'info', 'debug', 'warning', etc.",
        )


def add_input_arguments(
    parser: argparse.ArgumentParser,
    in_file_help: str = "input data file",
    include_input_group: bool = True,
):
    parser.add_argument(
        "--in-file",
        "-in",
        "-i",
        type=argparse.FileType("r"),
        # https://github.com/python/cpython/issues/58364
        help=in_file_help,
    )
    if include_input_group:
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
        return input_group


def add_output_arguments(
    parser: argparse.ArgumentParser,
    out_file_help: str = "output data file",
    include_output_group: bool = True,
):
    """
    Args:
        parser:
        output_format: Optional[str], use to specify explicit format,
            e.g. raw, bin, or hex
            leave off to allow all three formats as mutually exclusive group
    """
    parser.add_argument(
        "--out-file",
        "-out",
        "-o",
        type=argparse.FileType("w"),
        help=out_file_help,
    )
    if include_output_group:
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
        return output_group


@catch_exception
def main():
    parser = argparse.ArgumentParser(
        prog="bits",
        description=f"""
Convert input bits to bytes. 

Input and output formats can be specified independently, such that this command may 
be used as a converter between formats.

Examples:
    $ head -c 32 /dev/urandom | bits -1 -0x 

    $ echo 1001 | bits -1b -0b

    $ echo hello world | bits -1 -0""",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-v", "-V", "--version", action="version", version=bits.__version__
    )
    add_input_arguments(parser)
    add_output_arguments(parser)

    sub_parser = parser.add_subparsers(
        dest="subcommand",
        metavar="[subcommand]",
        # formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Use bits <subcommand> -h for help on each command""",
    )

    key_parser = sub_parser.add_parser(
        "key",
        help="generate private key",
        description="""
Generate Bitcoin private key integer.

This command support PEM encoded EC private key output, via the -0pem flag, for 
compatibility with external tools, e.g. openssl, if needed.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    key_parser_mutually_exclusive_output_group = add_output_arguments(key_parser)
    key_parser_mutually_exclusive_output_group.add_argument(
        "-0pem",
        dest="output_format_pem",
        action="store_true",
        help="output file format - PEM encoded private key",
    )

    pubkey_parser = sub_parser.add_parser(
        "pubkey",
        help="calculate public key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Calculate public key from private key integer. If the public key is provided as input, this 
sub-command may be used to compress / un-compress the key via the use of the -X flag.

This command support PEM encoded EC public key output, via the -0pem flag, for 
compatibility with external tools, e.g. openssl, if needed.""",
    )
    pubkey_parser.add_argument(
        "-X", "--compressed", action="store_true", help="output compressed pubkey"
    )
    add_input_arguments(pubkey_parser)
    pubkey_parser_mutually_exclusive_output_group = add_output_arguments(pubkey_parser)
    pubkey_parser_mutually_exclusive_output_group.add_argument(
        "-0pem",
        dest="output_format_pem",
        action="store_true",
        help="output file format - PEM encoded public key",
    )

    wif_parser = sub_parser.add_parser(
        "wif",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        help="encode WIF key",
        description="""
Encode a private key in eWIF (enhanced wallet import format).""",
    )
    wif_parser.add_argument(
        "--addr-type",
        "-T",
        metavar="addr_type",
        default="p2pkh",
        choices=[
            "p2pkh",
            "p2wpkh",
            "p2pk",
            "multisig",
            "p2sh-p2wpkh",
            "p2sh",
            "p2wsh",
            "p2sh-p2wsh",
        ],
        help="Address type. Valid choices are p2pkh, p2wpkh, p2pk, multisig, p2sh-p2wpkh, p2sh, p2wsh, or p2sh-p2wsh.",
    )
    wif_parser.add_argument(
        "--data",
        "-D",
        type=bytes.fromhex,
        help="additional data to append to WIF key before base58check encoding",
    )
    wif_parser.add_argument("--decode", action="store_true", help="decode wif")
    add_common_arguments(wif_parser)
    add_input_arguments(wif_parser, in_file_help="input private key data")
    add_output_arguments(
        wif_parser,
        out_file_help="output data file - raw binary",
        include_output_group=False,
    )

    addr_parser = sub_parser.add_parser(
        "addr",
        help="Encode Bitcoin addresses",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Encode Legacy or Segwit Bitcoin addresses from input payload. For p2pkh and p2sh, the 
input payload shall be the pubkeyhash (i.e. hash160(pubkey)) or scripthash (i.e. hash160(script)), 
respectively. Likewise, for witness v0 p2wpkh and p2wsh the input payload shall be pubkeyhash 
(i.e. hash160(pubkey)) or witness scripthash (i.e. hash256(script)), respectively.""",
    )
    addr_parser.add_argument(
        "-T",
        "--type",
        default="p2pkh",
        choices=[
            "p2pkh",
            "p2sh",
        ],
        metavar="addr_type",
        help="""
Address type. Valid choices are p2pkh or p2sh. Ignored when --witness-version is present.
        """,
    )
    addr_parser.add_argument(
        "--witness-version",
        type=int,
        help="""
Witness version for native Segwit addresses. 
Use of this option implies a Segwit address and addr_type (-T) is ignored.""",
        choices=range(17),
        metavar="witness_version",
    )
    add_common_arguments(addr_parser, include_log_level=False)
    add_input_arguments(addr_parser)
    add_output_arguments(
        addr_parser,
        out_file_help="output data file - raw binary",
        include_output_group=False,
    )

    mnemonic_parser = sub_parser.add_parser(
        "mnemonic",
        help="Generate and convert mnemonic phrases",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Generate or convert mnemonic phrase.

This command with no further options will generate a new mnemonic seed phrase.
When operating in this mode, the --strength (-S) argument can be used to specify the 
desired entropy strength, in bits. Alternatively, you may provide entropy bytes as input
when using the --from-entropy flag. The --to-entropy flag can be used to translate the 
mnemonic back to its orginal entropy. The --to-seed and --to-master-key flags can be 
used to convert the mnemonic phrase to the seed or master key, per BIP39 / BIP32, respectively.

Examples:

    1. Generate a mnemonic

        $ bits mnemonic

    2. Generate a mnemonic (specify entropy strength in bits)

        $ bits mnemonic -s 256

    3. Generate a mnemonic from provided entropy

        $ head -c 32 /dev/urandom | bits mnemonic -1 --from-entropy

    4. Retrieve original entropy

        $ echo <mnemonic-phrase> | bits mnemonic --to-entropy

    5. Convert mnemonic to seed

        $ echo <mnemonic-phrase> | bits mnemonic --to-seed

    6. Convert mnemonic to master key

        $ echo <mnemonic-phrase> | bits mnemonic --to-master-key""",
    )
    mnemonic_parser.add_argument(
        "--strength",
        "-s",
        metavar="STRENGTH",
        type=int,
        default=256,
        choices=[128, 160, 192, 224, 256],
        help="entropy strenghth (in bits) for mnemonic generation",
    )
    mnemonic_mutually_exclusive_group = mnemonic_parser.add_mutually_exclusive_group()
    mnemonic_mutually_exclusive_group.add_argument(
        "--from-entropy",
        action="store_true",
        help="""
        When this flag is present, converts entropy to mnemonic phrase.
            Note: in_file is entropy bytes and stdin may be used.
        """,
    )
    mnemonic_mutually_exclusive_group.add_argument(
        "--to-entropy",
        action="store_true",
        help="""
        When this flag is present, converts mnemonic phrase back to original entropy. 
            Note: in_file is mnemonic phrase and stdin may be used.
        """,
    )
    mnemonic_mutually_exclusive_group.add_argument(
        "--to-seed",
        action="store_true",
        help="""
        When this flag is present, converts mnemonic to seed per BIP39.
            Note: in_file is mnemonic phrase and stdin may be used.
        """,
    )
    mnemonic_mutually_exclusive_group.add_argument(
        "--to-master-key",
        action="store_true",
        help="""
        When this flag is present, converts mnemonic (to seed, and then) to master key per BIP32.
            Note: in_file is mnemonic phrase and stdin may be used.
        """,
    )
    add_common_arguments(mnemonic_parser)
    add_input_arguments(mnemonic_parser)
    add_output_arguments(mnemonic_parser)

    hd_parser = sub_parser.add_parser(
        "hd",
        help="Derive (or decode) extended keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Derive extended keys at a particular path, e.g "m/0'/1" or "M/0/0". 

The leading m/ or M/ in path indicate private or public derivation, respectively.
The extended key at which derivation starts need not be the root/master key.

Use --dump to deserialize & decode the derived key, and output json object to stderr. 
""",
    )
    hd_parser.add_argument("path", help="path to extended key, e.g. m/0'/1 or M/0'/1")
    hd_parser.add_argument(
        "--xpub",
        default=False,
        action="store_true",
        help="Use this flag to output the extended public key",
    )
    hd_parser.add_argument(
        "--dump",
        action="store_true",
        help="Deserialize extended key and decode as json. Writes to stderr.",
    )
    add_common_arguments(hd_parser, include_network=False)
    add_input_arguments(
        hd_parser,
        in_file_help="input data file - raw binary",
        include_input_group=False,
    )

    script_parser = sub_parser.add_parser(
        "script",
        help="Create arbitrary Bitcoin Scripts",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Create arbitrary Bitcoin Scripts. script_args shall either be OP_* or data. The script
will be properly encoded with data push opcodes, as necessary, but since these are implied, 
they should not be specified in script_args.

Use --decode to decode raw script input to opcodes / data.

Use --witness to indicate witness script encoding / decoding and to follow witness 
script semantics (include stack size push and difference in handling data push bytes) 

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
    P2WPKH:
        scriptPubkey: OP_0 <20-byte-pubkeyhash>
        scriptSig: (empty)
        witness: <sig> <pubkey>
    P2WSH:
        scriptPubkey: OP_0 <32-byte-scripthash>
        scriptSig: (empty)
        witness: <redeem-script>
    P2SH-P2WPKH:
        scriptPubkey: OP_HASH160 <20-byte-script-hash> OP_EQUAL
        scriptSig: Script(OP_0 <20-byte-pubkeyhash>)
        witness: <sig> <pubkey>
    P2SH-P2WSH:
        scriptPubkey: OP_HASH160 <20-byte-script-hash> OP_EQUAL
        scriptSig: Script(OP_0 <32-byte-script-hash>)
        witness: <redeem-script>""",
    )
    script_parser.add_argument(
        "script_args", nargs="*", help="Script arguments, e.g. OP_* or <data>"
    )
    script_parser.add_argument(
        "--decode",
        action="store_true",
        help="Use this flag to decode raw script input to opcodes / data.",
    )
    script_parser.add_argument(
        "--witness",
        action="store_true",
        help="Use this flag to indicate this is a witness script and to follow witness script encoding / decoding semantics.",
    )
    add_input_arguments(script_parser)
    add_output_arguments(script_parser)

    sig_parser = sub_parser.add_parser(
        "sig",
        help="Create or verify bitcoin signatures",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Create or verify Bitcoin signature

For signing, the input file shall be the private key. For verifying, the input file shall
be the public key.

A signature (sig) is created by taking the provided msg argument (msg shall be provided 
as a hex string), appending a 4-byte SIGHASH flag, hashing, signing, and appending the 
single byte SIGHASH.

The --msg-preimage flag can be used, to signify that the msg is the preimage and already
has the SIGHASH flag appended. The msg is still hashed, signed, and a single byte SIGHASH
appended.

Examples:
    $ bits sig -i <privatekey> <msg> --sighash all

    $ bits sig --verify -i <publickey> <msg> --signature <sig>""",
    )
    sig_parser.add_argument(
        "msg",
        help="message data to hash and sign (before sighash append)",
        type=bytes.fromhex,
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
    sig_parser.add_argument("--verify", action="store_true", help="verfiy signature")
    sig_parser.add_argument(
        "--signature", type=bytes.fromhex, help="signature in hex format"
    )
    sig_parser.add_argument(
        "--msg-preimage",
        action="store_true",
        help="indicates msg is pre-image, i.e. already has 4-byte sighash_flag appended. msg is still hashed, signed, then single-byte sighash_flag appended",
    )
    add_input_arguments(sig_parser)
    add_output_arguments(sig_parser)

    ripemd160_parser = sub_parser.add_parser(
        "ripemd160",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="ripemd160(data)",
        description="""Calculate ripemd160 of input data""",
    )
    add_input_arguments(ripemd160_parser)
    add_output_arguments(ripemd160_parser)

    sha256_parser = sub_parser.add_parser(
        "sha256", help="sha256(data)", description="""Calculate sha256 of input data"""
    )
    add_input_arguments(sha256_parser)
    add_output_arguments(sha256_parser)

    hash160_parser = sub_parser.add_parser(
        "hash160",
        help="HASH160(data)",
        description="Calculate HASH160 of input data, i.e. ripemd160(sha256(data))",
    )
    add_input_arguments(hash160_parser)
    add_output_arguments(hash160_parser)

    hash256_parser = sub_parser.add_parser(
        "hash256",
        help="HASH256(data)",
        description="Calculate HASH256 of input data, i.e. sha256(sha256(data))",
    )
    add_input_arguments(hash256_parser)
    add_output_arguments(hash256_parser)

    base58_parser = sub_parser.add_parser(
        "base58",
        help="base58 (check) encoding / decoding",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
        Base58(/check) encode / decode input data.
        """,
    )
    base58_parser.add_argument(
        "--check", default=False, action="store_true", help="base58check"
    )
    base58_parser.add_argument(
        "--decode", action="store_true", help="decode base58(check) input"
    )
    add_common_arguments(base58_parser)
    add_input_arguments(base58_parser)
    add_output_arguments(
        base58_parser,
        out_file_help="output data file - raw binary",
        include_output_group=False,
    )

    # TODO: improve help / description bech32
    bech32_parser = sub_parser.add_parser(
        "bech32", help="encode or decode bech32 or segwit data"
    )
    bech32_segwit_mutually_exclusive_group = bech32_parser.add_mutually_exclusive_group(
        required=True
    )
    bech32_segwit_mutually_exclusive_group.add_argument(
        "--hrp", type=os.fsencode, help="human readable part for bech32 encoding"
    )
    bech32_segwit_mutually_exclusive_group.add_argument(
        "--witness-version",
        type=int,
        help="witness version, if encoding a segwit address",
    )
    bech32_segwit_mutually_exclusive_group.add_argument(
        "--decode", action="store_true", help="Decode input data"
    )
    add_common_arguments(bech32_parser)
    add_input_arguments(bech32_parser)
    add_output_arguments(bech32_parser)

    tx_parser = sub_parser.add_parser(
        "tx",
        help="create raw transactions",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Create raw transactions.

Examples:

    1. Create raw transaction

        $ bits tx -txin '{"txid": "", "vout": 0, "scriptSig": ""}' -txout '{"satoshis": "", "scriptPubkey": ""}'

    2. Decode raw transaction

        $ echo <raw-tx> | bits tx --decode

        """,
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
    tx_parser.add_argument(
        "-v", "--version", type=int, default=1, help="transaction version"
    )
    tx_parser.add_argument(
        "-l", "--locktime", type=int, default=0, help="transaction locktime"
    )
    tx_parser.add_argument(
        "--script-witness",
        dest="script_witnesses",
        action="append",
        default=[],
        type=bytes.fromhex,
        help="witness script. This argument can be specified multiple times, but must appear in order corresponding to txins",
    )
    tx_parser.add_argument("--decode", action="store_true", help="decode raw tx")
    add_input_arguments(tx_parser)
    add_output_arguments(tx_parser)

    send_parser = sub_parser.add_parser(
        "send", help="Send funds from from_ addr to to_ addr."
    )
    send_parser.add_argument("from_", type=os.fsencode)
    send_parser.add_argument("to_", type=os.fsencode)
    send_parser.add_argument(
        "--miner-fee", type=int, default=1000, help="satoshis to include as miner fee"
    )
    send_parser.add_argument(
        "--version", "-v", type=int, default=1, help="transaction version"
    )
    send_parser.add_argument(
        "--locktime", type=int, default=0, help="transaction locktime"
    )
    send_parser.add_argument(
        "--sighash",
        choices=["all", "none", "single"],
        required=True,
        help="SIGHASH flag to use for signing (if key(s) are provided)",
    )
    send_parser.add_argument(
        "--anyone-can-pay",
        action="store_true",
        help="If present, ORs SIGHASH_FLAG with SIGHASH_ANYONECANPAY",
    )
    add_input_arguments(
        send_parser,
        in_file_help="wif unlocking key for from_ address",
        include_input_group=False,
    )
    add_output_arguments(send_parser)

    p2p_parser = sub_parser.add_parser("p2p", help="start p2p node")
    p2p_parser.add_argument(
        "--seeds", type=str, help="comma separated list of seed nodes"
    )

    blockchain_parser = sub_parser.add_parser(
        "blockchain",
        help="blockchain explorer",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Blockchain lulz
""",
    )
    blockchain_parser.add_argument("blockheight", type=int, help="block height")
    blockchain_parser.add_argument(
        "--header-only", "-H", action="store_true", help="output block header only"
    )
    add_output_arguments(blockchain_parser)

    mine_parser = sub_parser.add_parser(
        "mine",
        help="Mine blocks",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Mine blocks.
""",
    )
    mine_parser.add_argument(
        "--recv-addr",
        dest="recv_addr",
        type=os.fsencode,
        help="""Address to send block reward to.""",
    )
    mine_parser.add_argument(
        "--limit",
        type=int,
        help="Set a limit of the number of blocks to mine before exit. Useful in regtest mode for generating a set number of blocks",
    )
    add_common_arguments(mine_parser)

    rpc_parser = sub_parser.add_parser(
        "rpc",
        help="rpc interface",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="Send command to RPC node",
    )
    rpc_parser.add_argument("rpc_command", help="rpc command")
    rpc_parser.add_argument("params", nargs="*", help="params for rpc_command")
    rpc_parser.add_argument("-rpcurl", "--rpcurl", dest="rpc_url", help="rpc url")
    rpc_parser.add_argument("-rpcuser", "--rpcuser", dest="rpc_user", help="rpc user")
    rpc_parser.add_argument(
        "-rpcpassword", "--rpcpassword", dest="rpc_password", help="rpc password"
    )
    add_common_arguments(rpc_parser)

    args = parser.parse_args()
    update_config(args)

    bits.set_log_level(bits.bitsconfig["loglevel"])
    bits.p2p.set_magic_start_bytes(bits.bitsconfig["network"])

    if not args.subcommand:
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.write_bytes(
            data, args.out_file, output_format=bits.bitsconfig["output_format"]
        )
    elif args.subcommand == "key":
        # generate Bitcoin secret key
        privkey = bits.keys.key()
        if args.output_format_pem:
            privkey = bits.pem_encode_key(privkey)
            bits.write_bytes(privkey, args.out_file, output_format="raw")
            return
        bits.write_bytes(
            privkey, args.out_file, output_format=bits.bitsconfig["output_format"]
        )
    elif args.subcommand == "pubkey":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        if len(data) == 32:
            # privkey
            pk = bits.keys.pub(data, compressed=args.compressed)
        elif len(data) == 33 or len(data) == 65:
            # pubkey
            x, y = bits.point(data)
            pk = bits.pubkey(x, y, compressed=args.compressed)
        else:
            raise ValueError("data not recognized as private or public key")
        if args.output_format_pem:
            pk = bits.pem_encode_key(pk)
            bits.write_bytes(pk, args.out_file, output_format="raw")
            return
        bits.write_bytes(
            pk,
            args.out_file,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.subcommand == "mnemonic":
        if args.from_entropy:
            entropy = bits.read_bytes(
                args.in_file, input_format=bits.bitsconfig["input_format"]
            )
            mnemonic = bip39.calculate_mnemonic_phrase(entropy)
            bits.write_bytes(
                mnemonic.encode("utf8") + os.linesep.encode("utf8"),
                args.out_file,
                output_format="raw",
            )
        elif args.to_entropy or args.to_seed or args.to_master_key:
            mnemonic = bits.read_bytes(args.in_file, input_format="raw").decode("utf8")
            if args.to_entropy:
                bits.write_bytes(
                    bip39.to_entropy(mnemonic),
                    args.out_file,
                    output_format=bits.bitsconfig["output_format"],
                )
            elif args.to_seed or args.to_master_key:
                passphrase = getpass(prompt="passphrase: ")
                seed = bip39.to_seed(mnemonic, passphrase=passphrase)
                if args.to_master_key:
                    key, chaincode = bip32.to_master_key(seed)
                    xprv = bip32.root_serialized_extended_key(
                        key,
                        chaincode,
                        testnet=False
                        if bits.bitsconfig["network"] == "mainnet"
                        else True,
                    )
                    bits.write_bytes(
                        xprv,
                        args.out_file,
                        output_format="raw",
                    )
                    return
                bits.write_bytes(
                    seed, args.out_file, output_format=bits.bitsconfig["output_format"]
                )
        else:
            entropy = secrets.token_bytes(args.strength // 8)
            mnemonic = bip39.calculate_mnemonic_phrase(entropy)
            bits.write_bytes(
                mnemonic.encode("utf8") + os.linesep.encode("utf8"),
                args.out_file,
                output_format="raw",
            )
    elif args.subcommand == "hd":
        extended_key = bits.read_bytes(args.in_file, input_format="raw")
        derived_key = bits.wallet.hd.derive_from_path(args.path, extended_key)
        if args.xpub:
            derived_key = bits.wallet.hd.get_xpub(derived_key)
        if args.dump:
            sys.stderr.write(
                json.dumps(
                    bip32.deserialized_extended_key(derived_key, return_dict=True)
                )
                + os.linesep
            )
        bits.write_bytes(derived_key, args.out_file, output_format="raw")
    elif args.subcommand == "wif":
        if args.decode:
            wif_ = bits.read_bytes(args.in_file, input_format="raw")
            decoded = bits.wif_decode(wif_, return_dict=True)
            print(json.dumps(decoded))
            return
        privkey_ = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        wif = bits.utils.wif_encode(
            privkey_,
            addr_type=args.addr_type,
            data=args.data,
            network=bits.bitsconfig["network"],
        )
        bits.write_bytes(wif, args.out_file, output_format="raw")
    elif args.subcommand == "base58":
        if args.decode:
            data = bits.read_bytes(args.in_file, input_format="raw")
            if args.check:
                decoded = bits.base58.base58check_decode(data)
            else:
                decoded = bits.base58.base58decode(data)
            bits.write_bytes(decoded, output_format=bits.bitsconfig["output_format"])
            return
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        if args.check:
            encoded = bits.base58.base58check(data)
        else:
            encoded = bits.base58.base58encode(data)
        bits.write_bytes(encoded, output_format="raw")
    elif args.subcommand == "bech32":
        if args.decode:
            data_input = bits.read_bytes(args.in_file, input_format="raw")
            if bip173.is_segwit_addr(data_input):
                hrp, witness_version, witness_program = bip173.decode_segwit_addr(
                    data_input
                )
                print(
                    json.dumps(
                        {
                            "hrp": hrp.decode("utf8"),
                            "witness_version": witness_version,
                            "witness_program": witness_program.hex(),
                        }
                    )
                )
            else:
                hrp, data = bip173.parse_bech32(data_input)
                decoded_data = bip173.bech32_decode(data)
                bip173.assert_valid_bech32(hrp, data)
                print(
                    {
                        "hrp": hrp.decode("utf8"),
                        "data": decoded_data.hex(),
                    }
                )
            return
        data_input = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        if args.witness_version is not None:
            addr = bip173.segwit_addr(
                data,
                witness_version=args.witness_version,
                network=bits.bitsconfig["network"],
            )
            bits.write_bytes(args.out_file, output_format="raw")
        elif args.hrp is not None:
            encoded_data = bip173.bech32_encode(args.hrp, data_input)
            bits.write_bytes(encoded_data, output_format="raw")
        return
    elif args.subcommand == "ripemd160":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.write_bytes(
            bits.ripemd160(data),
            args.out_file,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.subcommand == "sha256":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.write_bytes(
            bits.sha256(data),
            args.out_file,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.subcommand == "hash160":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.write_bytes(
            bits.hash160(data),
            args.out_file,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.subcommand == "hash256":
        data = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        bits.write_bytes(
            bits.hash256(data),
            args.out_file,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.subcommand == "addr":
        payload = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        addr = bits.to_bitcoin_address(
            payload,
            addr_type=args.type,
            witness_version=args.witness_version,
            network=bits.bitsconfig["network"],
        )
        bits.write_bytes(addr, args.out_file, output_format="raw")
    elif args.subcommand == "tx":
        if args.decode:
            raw_tx = bits.read_bytes(
                args.in_file, input_format=bits.bitsconfig["input_format"]
            )
            decoded_tx, tx_prime = bits.tx.tx_deser(raw_tx)
            if tx_prime:
                log.warning(f"leftover tx data after deserialization: {tx_prime.hex()}")
            print(json.dumps(decoded_tx))
            return
        txins = []
        for txin_dict in args.txins:
            # internal byte order
            txid_ = bytes.fromhex(txin_dict["txid"])[::-1]
            # use script pub key as script sig for signing
            script_sig = bytes.fromhex(txin_dict["scriptSig"])
            txin_ = bits.tx.txin(bits.tx.outpoint(txid_, txin_dict["vout"]), script_sig)
            txins.append(txin_)
        txouts = [
            bits.tx.txout(
                txout_dict["satoshis"], bytes.fromhex(txout_dict["scriptPubKey"])
            )
            for txout_dict in args.txouts
        ]
        tx_ = bits.tx.tx(
            txins,
            txouts,
            version=args.version,
            locktime=args.locktime,
            script_witnesses=args.script_witnesses,
        )
        return tx_.hex()
    elif args.subcommand == "script":
        if args.decode:
            scriptbytes = bits.read_bytes(
                args.in_file, input_format=bits.bitsconfig["input_format"]
            )
            decoded = bits.script.decode_script(scriptbytes, witness=args.witness)
            print(json.dumps(decoded))
            return
        bits.write_bytes(
            bits.script.script(args.script_args, witness=args.witness),
            args.out_file,
            output_format=bits.bitsconfig["output_format"],
        )
    elif args.subcommand == "sig":
        if args.verify:
            if not args.signature:
                raise ValueError(
                    "--verify flag present without signature provided via --signature"
                )
            pubkey_ = bits.read_bytes(
                args.in_file, input_format=bits.bitsconfig["input_format"]
            )
            print(
                bits.sig_verify(
                    args.signature, pubkey_, args.msg, msg_preimage=args.msg_preimage
                )
            )
            return
        key = bits.read_bytes(
            args.in_file, input_format=bits.bitsconfig["input_format"]
        )
        sighash_flag = getattr(bits.script.constants, f"SIGHASH_{args.sighash.upper()}")
        if args.anyone_can_pay:
            sighash_flag |= bits.script.constants.SIGHASH_ANYONECANPAY
        sig = bits.sig(
            key, args.msg, sighash_flag=sighash_flag, msg_preimage=args.msg_preimage
        )
        bits.write_bytes(
            sig, args.out_file, output_format=bits.bitsconfig["output_format"]
        )
    elif args.subcommand == "send":
        if args.in_file:
            from_keys = bits.read_bytes(args.in_file, input_format="raw").split()
        sighash_flag = getattr(bits.script.constants, f"SIGHASH_{args.sighash.upper}")
        if args.anyone_can_pay:
            sighash_flag |= bits.script.constants.SIGHASH_ANYONECANPAY
        tx_ = bits.tx.send_tx(
            args.from_,
            args.to_,
            from_keys=from_keys,
            miner_fee=args.miner_fee,
            version=args.version,
            locktime=args.locktime,
            sighash_flag=sighash_flag,
        )
        bits.write_bytes(tx_, output_format=bits.bitsconfig["output_format"])

        send_question = input("Send transaction? (Y/N): ").strip()
        while send_question not in ["Y", "N"]:
            print("Input not recognized. Try again.")
            send_question = input("Send transaction? (Y/N): ").strip()
        if send_question == "Y":
            print(bits.rpc.rpc_method("sendrawtransaction", tx_.hex()))
        else:
            print("Transaction not sent.")
            return
    elif args.subcommand == "mine":
        n = 0
        while True:
            mine_block(args.recv_addr, network=bits.bitsconfig["network"])
            n += 1
            if args.limit and n >= args.limit:
                print(
                    f"{n} blocks mined. Reward sent to {args.recv_addr.decode('utf8')}"
                )
                break
    elif args.subcommand == "p2p":
        # bits p2p start --seeds "host1:port1,host2:port2"
        seeds = (
            args.seeds.split(",") if args.seeds else bits.bitsconfig.get("seeds", [])
        )
        if bits.bitsconfig.get("rpcbind"):
            rpc_host, rpc_port = bits.bitsconfig.get("rpcbind").split(":")
            rpc_port = int(rpc_port)
            rpc_bind = (rpc_host, rpc_port)
        else:
            rpc_bind = ()
        p2p_node = bits.p2p.Node(
            seeds=seeds,
            serve_rpc=bits.bitsconfig.get("serve"),
            rpc_bind=rpc_bind,
            rpc_username=bits.bitsconfig["rpcuser"],
            rpc_password=bits.bitsconfig["rpcpassword"],
        )
        p2p_node.start()
    elif args.subcommand == "blockchain":
        if args.blockheight == 0:
            bits.write_bytes(
                bits.blockchain.genesis_block(),
                args.out_file,
                output_format=bits.bitsconfig["output_format"],
            )
        else:
            raise NotImplementedError("blocks > 0 not implemented per v0")
    elif args.subcommand == "rpc":
        if args.rpc_url:
            bits.bitsconfig.update({"rpcurl": args.rpc_url})
        if args.rpc_user:
            bits.bitsconfig.update({"rpcuser": args.rpc_user})
        if args.rpc_password:
            bits.bitsconfig.update({"rpcpassword": args.rpc_password})

        result = bits.rpc.rpc_method(
            args.rpc_command,
            *args.params,
            rpc_url=bits.bitsconfig["rpcurl"],
            rpc_user=bits.bitsconfig["rpcuser"],
            rpc_password=bits.bitsconfig["rpcpassword"],
        )
        print(json.dumps(result) if type(result) is dict else result)
    else:
        raise ValueError("command not recognized")


if __name__ == "__main__":
    main()
