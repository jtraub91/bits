"""
Connect to a trusted Bitcoin RPC full node
"""
import base64
import json
from urllib.request import Request
from urllib.request import urlopen

with open("bits/config.json") as c:
    config = json.load(c)


def getnetworkinfo() -> dict:
    auth = f"{config['rpcUser']}:{config['rpcPassword']}"
    auth_b64 = base64.b64encode(auth.encode("ascii")).decode("ascii")
    headers = {"Content-Type": "text/plain", "Authorization": f"Basic {auth_b64}"}
    data = {
        "jsonrpc": "1.0",
        # "id": "curltest",
        "method": "getnetworkinfo",
        "params": [],
    }
    req = Request(
        config["rpcUrl"], headers=headers, data=json.dumps(data).encode("ascii")
    )
    ret = urlopen(req)
    return json.load(ret)["result"]
