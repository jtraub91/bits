"""
bits cli
"""
import argparse
import json
import os
import secrets
import signal
import sys
import time
from datetime import datetime, timezone
from getpass import getpass

import bits.base58
import bits.blockchain
import bits.crypto
import bits.p2p
import bits.pem
import bits.ordinals
import bits.script
import bits.tx
import bits.wallet.hd
from bits import __version__
from bits.bips import bip173
from bits.bips import bip32
from bits.bips import bip39
from bits.config import Config


class RawDescriptionDefaultsHelpFormatter(
    argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter
):
    pass


class ExplicitOption(argparse.Action):
    """
    Custom Action used for checking whether an option has been set explicitly
    (rather than by default)
    """

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, self.dest + "__explicit", True)


def send_fraction(f):
    """
    Cast to float and ensure float is within bounds [0.0, 1.0]
    """
    f = float(f)
    if f > 1.0:
        raise ValueError("fraction must be <= 1.0")
    elif f < 0.0:
        raise ValueError("fraction cannot be negative")
    return f


def add_common_arguments(
    parser: argparse.ArgumentParser,
    include_network: bool = True,
    include_log_level: bool = True,
):
    parser.add_argument(
        "--config-dir",
        type=str,
        action=ExplicitOption,
        help="Directory to look for optional config file (config.toml or config.json). "
        + "TOML will take precedence over JSON if both files are defined, "
        + "but TOML is only available for python 3.11+ ",
        default=os.path.join(os.path.expanduser("~"), ".bits"),
    )
    if include_network:
        parser.add_argument(
            "--network",
            "-N",
            metavar="NETWORK",
            type=str,
            default="mainnet",
            action=ExplicitOption,
            choices=["mainnet", "testnet", "regtest"],
            help="network, e.g. 'mainnet', 'testnet', or 'regtest'",
        )
    if include_log_level:
        parser.add_argument(
            "-L",
            "--log-level",
            default="error",
            action=ExplicitOption,
            metavar="LOG_LEVEL",
            choices=["trace", "debug", "info", "warning", "error"],
            help="log level, e.g. 'trace', 'debug', 'info', 'warning', or 'error'",
        )


def format_option(o):
    format_map = {
        "b": "bin",
        "x": "hex",
        "raw": "raw",
        "bin": "bin",
        "hex": "hex",
        "pem": "pem",
    }
    return format_map[o]


def add_input_arguments(
    parser: argparse.ArgumentParser,
    in_file_help: str = "input data file",
    include_input_format: bool = True,
):
    parser.add_argument(
        "--in-file",
        "-in",
        "-i",
        default="-",
        type=argparse.FileType("r"),
        # https://github.com/python/cpython/issues/58364
        help=in_file_help,
    )
    if include_input_format:
        parser.add_argument(
            "-1",
            "--input-format",
            metavar="INPUT_FORMAT",
            nargs="?",
            default="hex",
            const="raw",
            action=ExplicitOption,
            type=format_option,
            help="raw binary (-1), binary string (-1b), or hexadecimal string (-1x)",
        )


def add_output_arguments(
    parser: argparse.ArgumentParser,
    out_file_help: str = "output data file",
    include_output_format: bool = True,
):
    """
    Args:
        parser: ArgumentParser
        out_file_help: str
        include_output_format: bool
    """
    parser.add_argument(
        "--out-file",
        "-out",
        "-o",
        default="-",
        type=argparse.FileType("w"),
        help=out_file_help,
    )
    if include_output_format:
        parser.add_argument(
            "-0",
            "--output-format",
            metavar="OUTPUT_FORMAT",
            default="hex",
            const="raw",
            nargs="?",
            action=ExplicitOption,
            type=format_option,
            help="raw binary (-0), binary string (-0b), or hexadecimal string (-0x)",
        )


def setup_parser() -> argparse.ArgumentParser:
    """
    Setup argument parser
    Returns:
        argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="bits",
        description=f"""bits is a cli tool and pure Python library for Bitcoin.

See subcommands below for managing crypto, or use base command as follows.

Convert input bits to bytes. 

Input and output formats can be specified independently, such that this command may 
be used as a converter between formats.

Examples:
    $ head -c 8 /dev/urandom | bits -1 -0x 

    $ echo 1001 | bits -1b -0b

    $ echo hello world | bits -1 -0

""",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
    )
    parser.add_argument("-v", "-V", "--version", action="version", version=__version__)
    parser.add_argument(
        "-R", "--reverse-bytes", action="store_true", help="reverse byte order"
    )
    add_common_arguments(parser, include_network=False)
    add_input_arguments(parser)
    add_output_arguments(parser)

    sub_parser = parser.add_subparsers(
        dest="subcommand",
        metavar="[subcommand]",
        description="""
Use bits <subcommand> -h for help on each command""",
    )

    key_parser = sub_parser.add_parser(
        "key",
        help="Generate private key",
        description="""
Generate Bitcoin private key integer.

This command support PEM encoded EC private key output, via the --output-format argument, 
for compatibility with external tools, e.g. openssl, if needed.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_common_arguments(key_parser, include_network=False)
    add_output_arguments(key_parser, include_output_format=False)
    key_parser.add_argument(
        "-0",
        "--output-format",
        metavar="OUTPUT_FORMAT",
        nargs="?",
        default="hex",
        const="raw",
        action=ExplicitOption,
        type=format_option,
        help="raw binary (-0), binary string (-0b), hexadecimal string (-0x), or PEM-encoded private key (-0pem)",
    )

    pubkey_parser = sub_parser.add_parser(
        "pubkey",
        help="Calculate public key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Calculate public key from private key integer. If the public key is provided as input, this 
sub-command may be used to compress / un-compress the key via the use of the -X flag.

This command support PEM encoded EC public key output, via the --output-format argument,
for compatibility with external tools, e.g. openssl, if needed.""",
    )
    pubkey_parser.add_argument(
        "-X", "--compressed", action="store_true", help="output compressed pubkey"
    )
    add_common_arguments(pubkey_parser, include_network=False)
    add_input_arguments(pubkey_parser)
    add_output_arguments(pubkey_parser, include_output_format=False)
    pubkey_parser.add_argument(
        "-0",
        "--output-format",
        metavar="OUTPUT_FORMAT",
        nargs="?",
        default="hex",
        const="raw",
        type=format_option,
        help="raw binary (-0), binary string (-0b), hexadecimal string (-0x), or PEM-encoded public key (-0pem)",
    )

    wif_parser = sub_parser.add_parser(
        "wif",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        help="Encode (or decode) WIF key",
        description="""
Encode (or decode) a private key in eWIF (extended wallet import format).

This method builds upon extended WIF as seen in electrum wallet. The idea is that an 
eWIF indicates the corresponding address type, as well as, all information necessary to 
derive such, and, spend associated funds.

Extended WIF is backwards compatible with normal WIF.

Just as normal WIF is described as the base58check encoding of,

    version byte + private key + (optional 0x01 byte indicating a compressed pubkey) 

Extended WIF is defined as the base58check encoding of the following,

    (version byte + address type offset) + private key + (data)

Byte definitions:

    version

        mainnet -> 0x80
        testnet -> 0xEF
        regtest -> 0xEF

    address type offset

        p2pkh = 0,
        p2wpkh = 1
        p2sh-p2wpkh = 2
        p2pk = 3
        multisig = 4
        p2sh = 5
        p2wsh =  6
        p2sh-p2wsh = 7

    data

        p2pkh -> 0x01 byte for compressed pubkey, omit for uncompressed
        p2wpkh -> omit (compressed pubkey implied)
        p2sh-p2wpkh -> omit (compressed pubkey implied)
        p2pk -> 0x01 byte for compressed pubkey, omit for uncompressed
        multisig -> redeem script
        p2sh -> redeem script
        p2wsh -> redeem script
        p2sh-p2wsh -> witness script 
""",
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
        help="Address type",
    )
    wif_parser.add_argument(
        "--data",
        "-D",
        type=bytes.fromhex,
        help="additional data (hex) to append to WIF key before base58check encoding",
    )
    wif_parser.add_argument("--decode", action="store_true", help="decode wif")
    wif_parser.add_argument(
        "--print", "-P", action="store_true", help="print newline at end"
    )
    add_common_arguments(wif_parser)
    add_input_arguments(wif_parser, in_file_help="input private key data")
    add_output_arguments(
        wif_parser,
        out_file_help="output data file - raw binary",
        include_output_format=False,
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
        "--wv",
        type=int,
        help="""
Witness version for native Segwit addresses. 
Use of this option implies a Segwit address and addr_type (-T) is ignored.""",
        choices=range(17),
        metavar="witness_version",
    )
    addr_parser.add_argument(
        "--print", "-P", action="store_true", help="print newline at end"
    )
    add_common_arguments(addr_parser)
    add_input_arguments(addr_parser)
    add_output_arguments(
        addr_parser,
        out_file_help="output data file - raw binary",
        include_output_format=False,
    )

    mnemonic_parser = sub_parser.add_parser(
        "mnemonic",
        help="Generate (or convert) mnemonic phrases",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Generate (or convert) mnemonic phrase.

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

        $ bits mnemonic -S 256

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
        "-S",
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
    mnemonic_parser.add_argument(
        "--print", "-P", action="store_true", help="print newline at end"
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
        "-xpub",
        default=False,
        action="store_true",
        help="Use this flag to output the extended public key",
    )
    hd_parser.add_argument(
        "--dump",
        action="store_true",
        help="Deserialize extended key and decode as json. Write to stderr.",
    )
    hd_parser.add_argument(
        "--print", "-P", action="store_true", help="print newline at end"
    )
    add_common_arguments(hd_parser, include_network=False)
    add_input_arguments(
        hd_parser,
        in_file_help="input data file - raw binary",
        include_input_format=False,
    )

    script_parser = sub_parser.add_parser(
        "script",
        help="Create arbitrary Bitcoin Scripts",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Encode (or decode) arbitrary Bitcoin Script.

For encoding, script_args shall either be OP_* or data. The script
will be properly encoded with data push opcodes, as necessary, but since these are implied, 
they should not be specified in script_args.

For decoding, use the --decode flag. In this mode, script_args shall be any number of 
hex-encoded scripts, and will be decoded to to opcodes / data.

Use --witness to indicate witness script encoding / decoding and to follow witness 
script semantics (i.e. include stack size push and difference in handling data push bytes) 

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
        "script_args",
        nargs="*",
        help="Script arguments, e.g. OP_* or <data>. Or, hex-encoded script(s) when using --decode",
    )
    script_parser.add_argument(
        "--decode",
        action="store_true",
        help="Use this flag to decode hex-encoded script to opcodes / data.",
    )
    script_parser.add_argument(
        "--witness",
        action="store_true",
        help="Use this flag to indicate this is a witness script and to follow witness script encoding / decoding semantics.",
    )
    add_common_arguments(script_parser, include_network=False)

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
    add_common_arguments(sig_parser, include_network=False)
    add_input_arguments(sig_parser)
    add_output_arguments(sig_parser)

    ripemd160_parser = sub_parser.add_parser(
        "ripemd160",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="ripemd160(data)",
        description="""Calculate ripemd160 of input data""",
    )
    add_common_arguments(ripemd160_parser, include_network=False)
    add_input_arguments(ripemd160_parser)
    add_output_arguments(ripemd160_parser)

    sha256_parser = sub_parser.add_parser(
        "sha256", help="sha256(data)", description="""Calculate sha256 of input data"""
    )
    add_common_arguments(sha256_parser, include_network=False)
    add_input_arguments(sha256_parser)
    add_output_arguments(sha256_parser)

    hash160_parser = sub_parser.add_parser(
        "hash160",
        help="HASH160(data)",
        description="Calculate HASH160 of input data, i.e. ripemd160(sha256(data))",
    )
    add_common_arguments(hash160_parser, include_network=False)
    add_input_arguments(hash160_parser)
    add_output_arguments(hash160_parser)

    hash256_parser = sub_parser.add_parser(
        "hash256",
        help="HASH256(data)",
        description="Calculate HASH256 of input data, i.e. sha256(sha256(data))",
    )
    add_common_arguments(hash256_parser, include_network=False)
    add_input_arguments(hash256_parser)
    add_output_arguments(hash256_parser)

    base58_parser = sub_parser.add_parser(
        "base58",
        help="base58 (check) encoding / decoding",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
        Base58(/check) encode (or decode) input data.
        """,
    )
    base58_parser.add_argument(
        "--check", default=False, action="store_true", help="base58check"
    )
    base58_parser.add_argument(
        "--decode", action="store_true", help="decode base58(check) input"
    )
    base58_parser.add_argument(
        "--print", "-P", action="store_true", help="print newline at end"
    )
    add_common_arguments(base58_parser, include_network=False)
    add_input_arguments(base58_parser)
    add_output_arguments(
        base58_parser,
        out_file_help="output data file - raw binary",
        include_output_format=False,
    )

    bech32_parser = sub_parser.add_parser(
        "bech32", help="Encode (or decode) bech32 or segwit data"
    )
    bech32_mutually_exclusive_group = bech32_parser.add_mutually_exclusive_group(
        required=True
    )
    bech32_mutually_exclusive_group.add_argument(
        "--hrp",
        type=os.fsencode,
        help="human readable part for bech32 encoding",
    )
    bech32_parser.add_argument(
        "--witness-version",
        "--wv",
        type=int,
        help="witness version, if encoding a segwit address",
    )
    bech32_mutually_exclusive_group.add_argument(
        "--decode", action="store_true", help="Decode input data"
    )
    bech32_parser.add_argument(
        "--print", "-P", action="store_true", help="print newline at end"
    )
    add_common_arguments(bech32_parser, include_network=False)
    add_input_arguments(bech32_parser)
    add_output_arguments(bech32_parser)

    tx_parser = sub_parser.add_parser(
        "tx",
        help="create raw transactions",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Create, retrieve, and / or decode transactions.

Examples:

    1. Create raw transaction

        $ bits tx -txin '{"txid": "<txid>", "vout": <vout>, "scriptsig": "<scriptsig>"}' -txout '{"satoshis": <satoshis>, "scriptpubkey": "<scriptpubkey>"}'

    2. Decode raw transaction

        $ echo <rawtx> | bits tx --decode

    3. Retrieve tx from local blockchain
        
        $ bits tx <txid>
    
        """,
    )
    tx_parser.add_argument(
        "--datadir",
        type=str,
        action=ExplicitOption,
        help="p2p node data directory",
    )
    tx_parser.add_argument("txid", type=str, nargs="?", help="txid")
    tx_parser.add_argument(
        "-txin",
        "--txin",
        dest="txins",
        type=json.loads,
        action="append",
        default=[],
        help="""
        Transaction input data provided as a dictionary with the following keys: txid, vout, scriptsig.
        """,
    )
    tx_parser.add_argument(
        "-txout",
        "--txout",
        dest="txouts",
        type=json.loads,
        action="append",
        default=[],
        help="Transaction output data provided as a dictionary with the following keys: satoshis, scriptpubkey",
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
    tx_parser.add_argument(
        "--decode", action="store_true", help="decode raw tx to JSON from input file"
    )
    add_common_arguments(tx_parser, include_network=False)
    add_input_arguments(tx_parser)
    add_output_arguments(tx_parser)

    p2p_parser = sub_parser.add_parser("p2p", help="start p2p node")
    p2p_parser.add_argument(
        "--info", "-I", action="store_true", default=False, help="get p2p node info"
    )
    p2p_parser.add_argument(
        "--seeds",
        type=json.loads,
        action=ExplicitOption,
        help="list of seed nodes host:port, e.g. '[\"127.0.0.1:18333\"]'",
    )
    p2p_parser.add_argument(
        "--datadir",
        type=str,
        action=ExplicitOption,
        help="p2p node data directory",
    )
    p2p_parser.add_argument(
        "--reindex",
        action="store_true",
        help="reindex block indexes from blockheight 0",
    )
    p2p_parser.add_argument(
        "--headers-only",
        "-H",
        action="store_true",
        default=False,
        help="only download headers for IBD",
    )
    p2p_parser.add_argument(
        "--blocks-only",
        "-B",
        action="store_true",
        default=False,
        help="only download blocks for IBD",
    )
    p2p_parser.add_argument(
        "--assumevalid",
        type=int,
        default=0,
        help="assume block tx input scripts are valid, i.e. skip script verification, before blockheight",
    )
    add_common_arguments(p2p_parser)

    block_parser = sub_parser.add_parser(
        "block",
        help="retrieve and / or decode block data, or block chain info",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
Retrieve and / or decode blocks from local blockchain or input data.

Examples:
    bits block 0 -0

    bits block 100

    bits block 100 --decode

    echo <data> | bits block --decode

    bits block --chain-info

""",
    )
    block_parser.add_argument(
        "block", type=str, nargs="?", help="blockheight OR blockheaderhash"
    )
    block_parser.add_argument(
        "--datadir",
        type=str,
        action=ExplicitOption,
        help="p2p node data directory",
    )
    block_parser.add_argument(
        "--chain-info",
        "-I",
        action="store_true",
        default=False,
        help="get blockchain info",
    )
    block_parser.add_argument(
        "--index", action="store_true", default=False, help="print index data for block"
    )
    block_parser.add_argument(
        "--header-index",
        action="store_true",
        default=False,
        help="print blockheader index data from best peer chain",
    )
    block_parser.add_argument(
        "--header-only", "-H", action="store_true", help="output block header only"
    )
    block_parser.add_argument("--decode", action="store_true", help="decode block")
    add_common_arguments(block_parser)
    add_input_arguments(block_parser)
    add_output_arguments(block_parser)

    satoshi_parser = sub_parser.add_parser(
        "satoshi",
        help="get info on satoshis",
        formatter_class=RawDescriptionDefaultsHelpFormatter,
        description="""
        Get info on satoshi (see ordinal theory)

        You may provide:

        a) the satoshi, in integer, decimal, or name notation
        
        OR 
        
        b) degree notation per the --hour, --minute, --second, and --third flags

        For degree notation, all 4 flags must be provided 
        """,
    )
    satoshi_parser.add_argument(
        "satoshi",
        type=str,
        nargs="?",
        help="satoshi in integer, decimal, or name notation",
    )
    satoshi_parser.add_argument(
        "--hour",
        type=int,
        help="hour, the 1st integer per degree notation, i.e. cycle, numbered from 0",
    )
    satoshi_parser.add_argument(
        "--minute",
        type=int,
        help="minute, the 2nd integer per degree notation, i.e. index of block in halving epoch",
    )
    satoshi_parser.add_argument(
        "--second",
        type=int,
        help="second, the 3rd integer per degree notation, i.e. index of block in difficulty adjustment period",
    )
    satoshi_parser.add_argument(
        "--third",
        type=int,
        help="third, the 4th integer per degree notation, i.e. index of sat in block",
    )
    satoshi_parser.add_argument(
        "--utc",
        action="store_true",
        help="output satoshi timestamp in UTC (instead of local time)",
    )
    add_common_arguments(satoshi_parser)

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
        required=True,
        help="""Address to send block reward to.""",
    )
    mine_parser.add_argument(
        "--limit",
        type=int,
        help="Set a limit of the number of blocks to mine before exit. Useful in regtest mode for generating a set number of blocks",
    )
    add_common_arguments(mine_parser, include_network=False)
    return parser


def main():
    parser = setup_parser()
    args = parser.parse_args()

    config = Config(**vars(args))
    config.load_config(config_dir=args.config_dir)
    explicit_options = {
        option: value
        for option, value in vars(args).items()
        if getattr(args, option + "__explicit", False)
    }
    config.update(**explicit_options)
    log = bits.init_logging(config.log_level)

    if not args.subcommand:
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        if args.reverse_bytes:
            data = data[::-1]
        bits.write_bytes(data, args.out_file, output_format=config.output_format)
    elif args.subcommand == "key":
        # generate Bitcoin secret key
        privkey = bits.keys.key()
        if config.output_format == "pem":
            privkey = bits.pem.pem_encode_key(privkey)
            bits.write_bytes(privkey, args.out_file, output_format="raw")
            return
        bits.write_bytes(privkey, args.out_file, output_format=config.output_format)
    elif args.subcommand == "pubkey":
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        if len(data) == 32:
            # privkey
            pk = bits.keys.pub(data, compressed=args.compressed)
        elif len(data) == 33 or len(data) == 65:
            # pubkey
            x, y = bits.ecmath.point(data)
            pk = bits.pubkey(x, y, compressed=args.compressed)
        else:
            raise ValueError("data not recognized as private or public key")
        if config.output_format == "pem":
            pk = bits.pem.pem_encode_key(pk)
            bits.write_bytes(pk, args.out_file, output_format="raw")
            return
        bits.write_bytes(
            pk,
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "mnemonic":
        if args.from_entropy:
            entropy = bits.read_bytes(args.in_file, input_format=config.input_format)
            mnemonic = bip39.calculate_mnemonic_phrase(entropy)
            bits.write_bytes(
                (mnemonic + os.linesep).encode("utf8"),
                args.out_file,
                output_format="raw",
            )
        elif args.to_entropy or args.to_seed or args.to_master_key:
            mnemonic = (
                bits.read_bytes(args.in_file, input_format="raw").decode("utf8").strip()
            )
            # sanitize mnemonic to remove extra whitespace between words
            mnemonic = " ".join(mnemonic.split())
            if args.to_entropy:
                bits.write_bytes(
                    bip39.to_entropy(mnemonic),
                    args.out_file,
                    output_format=config.output_format,
                )
            elif args.to_seed or args.to_master_key:
                passphrase = getpass(prompt="passphrase: ")
                seed = bip39.to_seed(mnemonic, passphrase=passphrase)
                if args.to_master_key:
                    key, chaincode = bip32.to_master_key(seed)
                    xprv = bip32.root_serialized_extended_key(
                        key,
                        chaincode,
                        testnet=False if config.network == "mainnet" else True,
                    )
                    if args.print:
                        xprv += os.linesep.encode("utf8")
                    bits.write_bytes(
                        xprv,
                        args.out_file,
                        output_format="raw",
                    )
                    return
                bits.write_bytes(
                    seed, args.out_file, output_format=config.output_format
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
        if args.print:
            derived_key += os.linesep.encode("utf8")
        bits.write_bytes(derived_key, args.out_file, output_format="raw")
    elif args.subcommand == "wif":
        if args.decode:
            wif_ = bits.read_bytes(args.in_file, input_format="raw")
            decoded = bits.wif_decode(wif_, return_dict=True)
            print(json.dumps(decoded))
            return
        privkey_ = bits.read_bytes(args.in_file, input_format=config.input_format)
        wif = bits.wif_encode(
            privkey_,
            addr_type=args.addr_type,
            data=args.data,
            network=config.network,
        )
        if args.print:
            wif += os.linesep.encode("utf8")
        bits.write_bytes(wif, args.out_file, output_format="raw")
    elif args.subcommand == "base58":
        if args.decode:
            data = bits.read_bytes(args.in_file, input_format="raw")
            if args.check:
                decoded = bits.base58.base58check_decode(data)
            else:
                decoded = bits.base58.base58decode(data)
            if args.print:
                decoded += os.linesep.encode("utf8")
            bits.write_bytes(decoded, output_format=config.output_format)
            return
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        if args.check:
            encoded = bits.base58.base58check(data)
        else:
            encoded = bits.base58.base58encode(data)
        bits.write_bytes(encoded, output_format="raw")
    elif args.subcommand == "bech32":
        if args.decode:
            data_input = bits.read_bytes(args.in_file, input_format="raw")
            if bits.is_segwit_addr(data_input):
                hrp, witness_version, witness_program = bits.decode_segwit_addr(
                    data_input
                )
                print(
                    json.dumps(
                        {
                            "network": bip173.hrp_network_map[hrp],
                            "witness_version": witness_version,
                            "witness_program": witness_program.hex(),
                        }
                    )
                )
            else:
                hrp, payload = bip173.decode_bech32_string(data_input)
                print(
                    json.dumps(
                        {
                            "hrp": hrp.decode("utf8"),
                            "payload": payload.hex(),
                        }
                    )
                )
            return
        data_input = bits.read_bytes(args.in_file, input_format=config.input_format)
        witness_version_byte = (
            bip173.bech32_chars[args.witness_version : args.witness_version + 1]
            if args.witness_version is not None
            else b""
        )
        encoded_data = bip173.bech32_encode(
            args.hrp, data_input, witness_version=witness_version_byte
        )
        if args.print:
            encoded_data += os.linesep.encode("utf8")
        bits.write_bytes(encoded_data, args.out_file, output_format="raw")
    elif args.subcommand == "ripemd160":
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        bits.write_bytes(
            bits.crypto.ripemd160(data),
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "sha256":
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        bits.write_bytes(
            bits.crypto.sha256(data),
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "hash160":
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        bits.write_bytes(
            bits.crypto.hash160(data),
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "hash256":
        data = bits.read_bytes(args.in_file, input_format=config.input_format)
        bits.write_bytes(
            bits.crypto.hash256(data),
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "addr":
        payload = bits.read_bytes(args.in_file, input_format=config.input_format)
        addr = bits.to_bitcoin_address(
            payload,
            addr_type=args.type,
            witness_version=args.witness_version,
            network=config.network,
        )
        if args.print:
            addr += os.linesep.encode("utf8")
        bits.write_bytes(addr, args.out_file, output_format="raw")
    elif args.subcommand == "tx":
        if args.txid:
            node = bits.p2p.Node(
                config.seeds,
                config.datadir,
                config.network,
                config.log_level,
                max_outgoing_peers=config.max_outgoing_peers,
            )
            tx_index = node.db.get_tx(args.txid)
            block_index = node.db.get_block(blockheaderhash=tx_index["blockheaderhash"])
            block = node.get_block_data(
                os.path.join(node.datadir, block_index["datafile"]),
                block_index["datafile_offset"],
            )
            tx_ = bits.tx.tx_ser(block["txns"][tx_index["n"]])
        elif args.txins or args.txouts:
            txins = []
            for txin_dict in args.txins:
                # internal byte order
                txid_ = bytes.fromhex(txin_dict["txid"])[::-1]
                # use script pub key as script sig for signing
                script_sig = bytes.fromhex(txin_dict["scriptsig"])
                txin_ = bits.tx.txin(
                    bits.tx.outpoint(txid_, txin_dict["vout"]), script_sig
                )
                txins.append(txin_)
            txouts = [
                bits.tx.txout(
                    txout_dict["satoshis"], bytes.fromhex(txout_dict["scriptpubkey"])
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
        else:
            tx_ = bits.read_bytes(args.in_file, input_format=config.input_format)
        if args.decode:
            decoded_tx, tx_prime = bits.tx.tx_deser(tx_)
            if tx_prime:
                log.warning(f"leftover tx data after deserialization: {tx_prime.hex()}")
            print(json.dumps(decoded_tx))
            return
        bits.write_bytes(tx_, args.out_file, output_format=args.output_format)
    elif args.subcommand == "script":
        if args.decode:
            decoded = []
            for script in args.script_args:
                script_bytes = bytes.fromhex(script)
                script_decoded = bits.script.decode_script(
                    script_bytes, witness=args.witness
                )
                decoded.append(script_decoded)
            print(json.dumps(decoded))
            return
        bits.write_bytes(
            bits.script.script(args.script_args, witness=args.witness),
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "sig":
        if args.verify:
            if not args.signature:
                raise ValueError(
                    "--verify flag present without signature provided via --signature"
                )
            pubkey_ = bits.read_bytes(args.in_file, input_format=config.input_format)
            print(
                bits.script.sig_verify(
                    args.signature, pubkey_, args.msg, msg_preimage=args.msg_preimage
                )
            )
            return
        key = bits.read_bytes(args.in_file, input_format=config.input_format)
        sighash_flag = getattr(bits.constants, f"SIGHASH_{args.sighash.upper()}")
        if args.anyone_can_pay:
            sighash_flag |= bits.constants.SIGHASH_ANYONECANPAY
        sig = bits.script.sig(
            key, args.msg, sighash_flag=sighash_flag, msg_preimage=args.msg_preimage
        )
        bits.write_bytes(sig, args.out_file, output_format=config.output_format)
    elif args.subcommand == "mine":
        raise NotImplementedError  # yet
    elif args.subcommand == "p2p":
        if args.headers_only and args.blocks_only:
            log.error("only one of --headers-only or --blocks-only may be supplied")
            return
        elif args.headers_only or args.blocks_only:
            download_headers = True if args.headers_only else False
            download_blocks = True if args.blocks_only else False
        else:
            download_blocks = True
            download_headers = True
        p2p_node = bits.p2p.Node(
            config.seeds,
            config.datadir,
            config.network,
            config.log_level,
            max_outgoing_peers=config.max_outgoing_peers,
            download_headers=download_headers,
            download_blocks=download_blocks,
            assumevalid=args.assumevalid,
        )
        if args.info:
            node_info = p2p_node.get_node_info()
            print(json.dumps(node_info))
            return
        if args.reindex:
            key = input(f"reindex from blockheight 0? (y/n) ")
            if key != "y":
                print("reindex cancelled")
                return
        p2p_node.start(reindex=args.reindex)

        def shutdown(*args):
            p2p_node.stop()

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)
        p2p_node._thread.join()
    elif args.subcommand == "block":
        if args.chain_info:
            node = bits.p2p.Node(
                config.seeds,
                config.datadir,
                config.network,
                config.log_level,
                max_outgoing_peers=config.max_outgoing_peers,
            )
            print(json.dumps(node.get_blockchain_info()))
            return
        if args.block is None:
            block = bits.read_bytes(args.in_file, input_format=config.input_format)
            header = block[:80]
        else:
            node = bits.p2p.Node(
                config.seeds,
                config.datadir,
                config.network,
                config.log_level,
                max_outgoing_peers=config.max_outgoing_peers,
            )
            if len(args.block) == 64:
                # if provided arg is 64 digits, it is interpreted as a hash
                if args.header_index:
                    best_peer_id = node.get_best_peer()
                    block_index_data = node.db.get_blockheader(
                        best_peer_id, blockheaderhash=args.block
                    )
                else:
                    block_index_data = node.db.get_block(blockheaderhash=args.block)
            else:
                # else a blockheight
                if args.header_index:
                    best_peer_id = node.get_best_peer()
                    block_index_data = node.db.get_blockheader(
                        best_peer_id, blockheight=int(args.block)
                    )
                else:
                    block_index_data = node.db.get_block(blockheight=int(args.block))
            if not block_index_data:
                log.error(f"no index data found for block {args.block}")
                return
            if args.index or args.header_index:
                print(json.dumps(block_index_data))
                return
            block = node.get_block_data(
                os.path.join(node.datadir, block_index_data["datafile"]),
                block_index_data["datafile_offset"],
            )
            header = block[:80]
        if args.decode:
            block = bits.blockchain.block_deser(block)
            header = bits.blockchain.block_header_deser(header)
            print(json.dumps(header if args.header_only else block))
            return
        bits.write_bytes(
            header if args.header_only else block,
            args.out_file,
            output_format=config.output_format,
        )
    elif args.subcommand == "satoshi":
        if args.satoshi is not None:
            try:
                sat = int(args.satoshi)
            except ValueError:
                if "." in args.satoshi:
                    sat = bits.ordinals.from_decimal(args.satoshi)
                else:
                    # name
                    # TODO: more rigorous check if it's a name
                    sat = bits.ordinals.from_name(args.satoshi)
        else:
            if all(
                [
                    args.hour is not None,
                    args.minute is not None,
                    args.second is not None,
                    args.third is not None,
                ]
            ):
                sat = bits.ordinals.from_degree(
                    f"{args.hour}°{args.minute}′{args.second}″{args.third}‴"
                )
            else:
                log.error(
                    "either satoshi or all of hour, minute, second, and third must be provided"
                )
                return

        node = bits.p2p.Node(
            config.seeds,
            config.datadir,
            config.network,
            config.log_level,
            max_outgoing_peers=config.max_outgoing_peers,
        )
        chain_info = node.get_blockchain_info()
        sat_block = int(bits.ordinals.decimal(sat).split(".")[0])
        if sat_block <= chain_info["height"]:
            block_index_data = node.db.get_block(blockheight=sat_block)
            n_time = block_index_data["nTime"]
            strf_format = (
                "%Y-%m-%d %H:%M:%S %Z"
                if args.utc
                else f"%Y-%m-%d %H:%M:%S {time.tzname[time.daylight]}"
            )
            timestamp = datetime.fromtimestamp(
                n_time, tz=timezone.utc if args.utc else None
            ).strftime(strf_format)
        else:
            best_time = chain_info["time"]
            n_time_expected = best_time + (sat_block - chain_info["height"]) * 60 * 10
            strf_format = (
                "%Y-%m-%d %H:%M:%S %Z (expected)"
                if args.utc
                else f"%Y-%m-%d %H:%M:%S {time.tzname[time.daylight]} (expected)"
            )
            timestamp = datetime.fromtimestamp(
                n_time_expected, tz=timezone.utc if args.utc else None
            ).strftime(strf_format)
        print(
            json.dumps(
                {
                    "satoshi": sat,
                    "decimal": bits.ordinals.decimal(sat),
                    "percentile": bits.ordinals.percentile(sat),
                    "degree": bits.ordinals.degree(sat),
                    "name": bits.ordinals.name(sat),
                    "rarity": bits.ordinals.rarity(sat),
                    "timestamp": timestamp,
                }
            )
        )
    else:
        raise ValueError("command not recognized")


if __name__ == "__main__":
    main()
