# derive a mnemonic seed and child keys
# send money on test net
# restore funds from seed

from mnemonic import Mnemonic


def generate_seed():
    seed = Mnemonic("english").generate()
    return seed






if __name__ == "__main__":
    print(main())
