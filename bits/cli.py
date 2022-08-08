import argparse

import ecdsa

from bits.keys import generate_keypair
from bits.utils import to_bitcoin_address

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("-v", dest="verbose", action="store_true", default=False)
    args = parser.parse_args()

    if args.command == "generate_keys":
        pk1, (x1, y1) = generate_keypair(save_as="key1.pem")
        if args.verbose:
            print(f"keys 1:")
            print("---")
            print(f"private: {pk1}")
            print(f"public: ({x1}, {y1})")
            bitcoin_addr1 = to_bitcoin_address(x1, y1, network="testnet")
            print(f"addr: {bitcoin_addr1}")
            print(f"---")
            pk2, (x2, y2) = generate_keypair(save_as="key2.pem")
            print(f"keys 2:")
            print("---")
            print(f"private: {pk2}")
            print(f"public: ({x2}, {y2})")
            bitcoin_addr2 = to_bitcoin_address(x2, y2, network="testnet")
            print(f"addr: {bitcoin_addr2}")
            print("---")
    elif args.command == "import_keys":
        with open("key1.pem", "rb") as key1_file:
            key1_pem = key1_file.read()
        sk1 = ecdsa.SigningKey.from_pem(key1_pem)
        if args.verbose:
            private_key_1 = sk1.privkey.secret_multiplier
            x1, y1 = (
                sk1.verifying_key.pubkey.point.x(),
                sk1.verifying_key.pubkey.point.y(),
            )
            addr1 = to_bitcoin_address(x1, y1, network="testnet")
            print("key1.pem")
            print(f"secret: {private_key_1}")
            print(f"public (x,y): ({x1}, {y1})")
            print(f"bitcoin addr: {addr1}")
            print("---")

        with open("key2.pem", "rb") as key2_file:
            key2_pem = key2_file.read()
        sk2 = ecdsa.SigningKey.from_pem(key2_pem)
        if args.verbose:
            private_key_2 = sk2.privkey.secret_multiplier
            x2, y2 = (
                sk2.verifying_key.pubkey.point.x(),
                sk2.verifying_key.pubkey.point.y(),
            )
            addr2 = to_bitcoin_address(x2, y2, network="testnet")
            print("key2.pem")
            print(f"secret: {private_key_2}")
            print(f"public (x,y): ({x2}, {y2})")
            print(f"bitcoin addr: {addr2}")
            print("---")
