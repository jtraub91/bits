import logging
import os

log = logging.getLogger(__name__)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s [%(name)s] %(message)s")
if not os.path.exists(".bits/logs"):
    os.makedirs(".bits/logs")
fh = logging.FileHandler(".bits/logs/bits.log")
fh.setFormatter(formatter)
sh = logging.StreamHandler()
sh.setFormatter(formatter)
log.addHandler(fh)
log.addHandler(sh)


def set_log_level(level: str):
    if level.lower() not in ["info", "debug", "warning", "critical", "error"]:
        raise ValueError(f"log level not supported: {level}")
    log.setLevel(getattr(logging, level.upper()))
    return True


def default_config():
    return {
        "network": "mainnet",
        "log_level": "info",
        "rpcurl": "",
        "rpcuser": "",
        "rpcpassword": "",
    }
