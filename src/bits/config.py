import json
import os

try:
    import tomllib

    HAS_TOMLLIB = True
except ImportError:
    HAS_TOMLLIB = False


class Config(object):
    def __init__(self, **kwargs):
        self.network = kwargs.get("network", "mainnet")
        self.logfile = kwargs.get(
            "logfile", os.path.join(os.path.expanduser("~"), ".bits", "log", "bits.log")
        )
        self.loglevel = kwargs.get("loglevel", "error")
        self.input_format = kwargs.get("input_format", "hex")
        self.output_format = kwargs.get("output_format", "hex")

    def load_config(self):
        """
        Look for configuration in ~/.bits and load, if present
        """
        if HAS_TOMLLIB and os.path.exists(
            os.path.join(os.path.expanduser("~"), ".bits", "config.toml")
        ):
            with open(
                os.path.join(os.path.expanduser("~"), ".bits", "config.toml"), "rb"
            ) as config_file:
                config_file_dict = tomllib.load(config_file)
        elif os.path.exists(
            os.path.join(os.path.expanduser("~"), ".bits", "config.json")
        ):
            with open(
                os.path.join(os.path.expanduser("~"), ".bits", "config.json")
            ) as config_file:
                config_file_dict = json.load(config_file)
        else:
            config_file_dict = {}

        if config_file_dict:
            # update config - current attrs updated with defined config file attrs
            # re __init__ to avoid applying invalid keys
            config_file_dict = vars(self).update(config_file_dict)
            self.__init__(**config_file_dict)
