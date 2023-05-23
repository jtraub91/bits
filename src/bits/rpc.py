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
log.setLevel(logging.DEBUG)


def rpc_method(
    method, *params, rpc_url="", rpc_user="", rpc_password="", rpc_datadir=""
) -> Union[dict, str]:
    """
    Call a method (w/ params) to bitcoind node
    """
    if not rpc_url:
        raise ValueError("rpc_url must be defined")
    if rpc_datadir:
        if not os.path.exists(os.path.join(rpc_datadir, ".cookie")):
            raise ValueError(
                f".cookie file not found in {os.path.join(rpc_datadir, '.cookie')}"
            )
        with open(os.path.join(rpc_datadir, ".cookie")) as cookie_file:
            cookie = cookie_file.read()
        auth = cookie
    else:
        if not (rpc_user and rpc_password):
            raise ValueError(
                "rpc_user and rpc_password must be defined for non-cookie based rpc auth. "
                + "For cookie-based auth, please specify rpc_datadir."
            )
        auth = f"{rpc_user}:{rpc_password}"

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
    req = Request(rpc_url, headers=headers, data=json.dumps(data).encode("ascii"))
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
