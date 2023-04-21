"""
RPC
"""
import base64
import json
import logging
import os
import time
from typing import Union
from urllib.error import HTTPError
from urllib.request import Request
from urllib.request import urlopen

import bits

log = logging.getLogger(__name__)


def rpc_method(
    method, *params, rpcurl="", rpcuser="", rpcpassword="", datadir=""
) -> Union[dict, str]:
    """
    Call a method (w/ params) to bitcoind node
    """
    if not rpcurl:
        raise ValueError("rpcurl must be defined")
    if datadir:
        if not os.path.exists(os.path.join(datadir, ".cookie")):
            raise ValueError(
                f".cookie file not found in {os.path.join(datadir, '.cookie')}"
            )
        with open(os.path.join(datadir, ".cookie")) as cookie_file:
            cookie = cookie_file.read()
        auth = cookie
    else:
        if not (rpcuser and rpcpassword):
            raise ValueError(
                "rpcuser and rpcpassword must be defined for non-cookie based rpc auth. "
                + "For cookie-based auth, please specify datadir."
            )
        auth = f"{rpcuser}:{rpcpassword}"

    auth_b64 = base64.b64encode(auth.encode("ascii")).decode("ascii")
    headers = {"Content-Type": "text/plain", "Authorization": f"Basic {auth_b64}"}

    formatted_params = []
    for param in params:
        try:
            formatted_params.append(int(param))
        except ValueError as value_error:
            try:
                formatted_params.append(json.loads(param))
            except json.decoder.JSONDecodeError as json_error:
                log.debug(
                    f"JSONDecodeError - '{json_error}'. Continuing with param as string..."
                )
                formatted_params.append(param)

    data = {
        "jsonrpc": "1.0",
        "id": f"bits_rpc_{method}_{int(time.time())}",
        "method": method,
        "params": formatted_params,
    }
    req = Request(rpcurl, headers=headers, data=json.dumps(data).encode("ascii"))
    try:
        ret = urlopen(req)
        result = json.load(ret)["result"]
        return result
    except HTTPError as http_error:
        ret = json.load(http_error.file)
        detail = {
            "id": ret["id"],
            "code": ret["error"]["code"],
            "message": ret["error"]["message"],
        }
        log.error(f"{http_error.code} - {http_error.msg} {detail}")
        return ret["error"]["message"]
