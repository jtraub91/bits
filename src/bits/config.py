import copy
import json
import os

try:
    import tomllib

    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False


class Config(object):
    def __init__(self, **kwargs):
        self.log_level = kwargs.get("log_level", "error")
        self.network = kwargs.get("network", "mainnet")

        self.datadir = kwargs.get("datadir", "")
        self.seeds = kwargs.get("seeds", [])
        self.max_outgoing_peers = kwargs.get("max_outgoing_peers", 5)
        self.miner_wallet_address = kwargs.get("miner_wallet_address", "")
        self.bind = kwargs.get("bind", None)
        self.index_ordinals = kwargs.get("index_ordinals", False)

        self.input_format = kwargs.get("input_format", "hex")
        self.output_format = kwargs.get("output_format", "hex")

    def load_config(
        self, config_dir: str = os.path.join(os.path.expanduser("~"), ".bits")
    ):
        """
        Look for configuration file in ~/.bits and load, if present
        """
        if HAS_TOMLLIB and os.path.exists(os.path.join(config_dir, "config.toml")):
            with open(os.path.join(config_dir, "config.toml"), "rb") as config_file:
                config_file_dict = tomllib.load(config_file)
        elif os.path.exists(os.path.join(config_dir, "config.json")):
            with open(os.path.join(config_dir, "config.json")) as config_file:
                config_file_dict = json.load(config_file)
        else:
            config_file_dict = {}

        if config_file_dict:
            # update config - current attrs updated with defined config file attrs
            # re __init__ to avoid applying invalid keys
            config_update = copy.deepcopy(vars(self))
            config_update.update(config_file_dict)
            self.__init__(**config_update)

    def update(self, **kwargs):
        """
        Update Config with kwargs

        Avoid applying keys not defined in __init__ by re-instantiating
        """
        updated_attrs = copy.deepcopy(vars(self))
        updated_attrs.update(kwargs)
        self.__init__(**updated_attrs)
