"""
PAN-OS XML API client — ported from collect_data.py's api_call()/get_api_key().

Phase 2 work (not yet wired to an endpoint beyond the 501 stub in main.py):
a live assessment would call get_api_key() once, then api_call() for the same
op/config requests collect_data.py already issues, and hand each response
root to the matching parser.py function (parse_system_info(config_root,
op_root=...), parse_licenses(op_root=...), parse_ha(op_root=...)) alongside
a full config export's root for the config-only sections — giving the rules
engine a fully "available" data dict instead of today's file-upload one.
"""

from __future__ import annotations

import ssl
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def get_api_key(host: str, user: str, password: str) -> Optional[str]:
    params = urllib.parse.urlencode({"type": "keygen", "user": user, "password": password})
    url = f"https://{host}/api/?{params}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=15) as resp:
        root = ET.fromstring(resp.read())
        key = root.find(".//key")
        return key.text if key is not None else None


def api_call(host: str, api_key: str, xpath: Optional[str] = None,
             op_cmd: Optional[str] = None, timeout: int = 30) -> Optional[ET.Element]:
    if op_cmd:
        params = {"type": "op", "cmd": op_cmd, "key": api_key}
    else:
        params = {"type": "config", "action": "get", "xpath": xpath, "key": api_key}

    url = f"https://{host}/api/?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
        raw = resp.read()
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None
