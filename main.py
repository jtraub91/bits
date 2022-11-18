from bits.p2p import Node
from bits.p2p import set_magic_start_bytes

if __name__ == "__main__":
    set_magic_start_bytes("testnet")
    p2p_node = Node(
        [
            "traub-box-1:18333",
        ]
    )
    p2p_node.start()
    import IPython

    IPython.embed()
