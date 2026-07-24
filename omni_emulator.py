#!/usr/bin/env python3
"""Aslan Omni terminal + cloud-device emulator (stdlib only)."""
import argparse
import hashlib
import hmac
import json
import queue
import random
import secrets
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Scenario table (same as the NAPS emulator) ──────────────────────────────
SCENARIOS = {
    "insufficient_funds": "116",
    "wrong_pin": "117",
    "pin_attempts_exceeded": "106",
    "expired_card": "101",
    "suspected_fraud": "102",
    "do_not_honour": "100",
    "card_not_active": "118",
    "transaction_not_allowed": "120",
    "exceeds_limits": "121",
    "use_chip": "265",
    "pin_failed": "281",
    "system_down": "909",
    "issuer_unavailable": "912",
    "server_error": "995",
}


def resolve_code(code: str) -> str:
    """Map a scenario name to its numeric RC; pass a numeric code through unchanged."""
    return SCENARIOS.get(code, code)


# ── Amount-suffix magic values (deterministic outcomes for CI) ──────────────
_MAGIC = {0: "approved", 5: "declined", 8: "cancelled", 51: "timeout"}


def magic_outcome(amount_centimes: int) -> str | None:
    """Return an outcome forced by the amount's last two digits, or None."""
    suffix = amount_centimes % 100
    if suffix == 51:
        return "timeout"
    if suffix in (0, 5, 8):
        return _MAGIC[suffix]
    return None


# ── HMAC / hashing ──────────────────────────────────────────────────────────
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def lan_expected_sig(token_hmac_hex: str, token_id: str, ts: str,
                     method: str, path: str, body: bytes) -> str:
    """The signature the emulator expects for an inbound LAN request.

    Derived-key scheme: key = hexToBytes(tokenHmac); tokenHmac was HMAC(secret, tokenId).
    """
    key = bytes.fromhex(token_hmac_hex)
    msg = f"{token_id}:{ts}:{method}:{path}:{sha256_hex(body)}"
    return hmac_hex(key, msg.encode())


def device_sig(device_token: str, ts: str, method: str, path: str, body: bytes) -> str:
    """The signature the emulator SENDS as a cloud device.

    Raw-key scheme: key = deviceToken utf-8; message includes the token as tokenId.
    """
    msg = f"{device_token}:{ts}:{method}:{path}:{sha256_hex(body)}"
    return hmac_hex(device_token.encode(), msg.encode())


def device_auth_header(device_token: str, method: str, path: str, body: bytes) -> str:
    ts = str(int(time.time()))
    sig = device_sig(device_token, ts, method, path, body)
    return f"OMNI-TOKEN tokenId={device_token},ts={ts},sig={sig}"
