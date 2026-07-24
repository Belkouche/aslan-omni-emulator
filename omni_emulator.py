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


# ── Outcome engine ──────────────────────────────────────────────────────────
def _gen_stan() -> str:  return f"{random.randint(1, 999999):06d}"
def _gen_auth() -> str:  return f"{random.randint(100000, 999999)}"
def _gen_rrn() -> str:   return f"{random.randint(0, 10**12 - 1):012d}"

MASKED_CARD = "516794******3315"
CARD_SCHEME = "MASTERCARD"


def decide_outcome(amount_centimes: int, mode: str, error_code: str) -> dict:
    """Resolve a payment to an outcome. Magic amount overrides mode."""
    status = magic_outcome(amount_centimes)
    rc = "000"

    if status is None:
        if mode == "approve":
            status = "approved"
        elif mode == "decline":
            status, rc = "declined", "005"
        elif mode == "error":
            status, rc = "declined", resolve_code(error_code)
        elif mode == "timeout":
            status = "timeout"
        else:  # "interactive" — caller overrides this with ask_operator(); default approve
            status = "approved"
    elif status == "declined":
        rc = "005"

    out = {"status": status, "responseCode": rc if status in ("approved", "declined") else None}
    if status == "approved":
        now = datetime.now()
        out.update({
            "authNumber": _gen_auth(),
            "stan": _gen_stan(),
            "rrn": _gen_rrn(),
            "cardNumber": MASKED_CARD,
            "cardScheme": CARD_SCHEME,
            "transactionDate": now.strftime("%d/%m/%Y"),
            "transactionTime": now.strftime("%H:%M:%S"),
        })
    return out


def pay_result(ref: str, amount_centimes: int, outcome: dict,
               terminal_id: str = "EMU-TID", merchant_id: str = "EMU-MID") -> dict:
    """Assemble the flat PayResult JSON the SDK expects (LAN /pay + cloud share it)."""
    return {
        "status": outcome["status"],
        "ref": ref,
        "responseCode": outcome.get("responseCode"),
        "authNumber": outcome.get("authNumber"),
        "stan": outcome.get("stan"),
        "rrn": outcome.get("rrn"),
        "cardNumber": outcome.get("cardNumber"),
        "cardScheme": outcome.get("cardScheme"),
        "terminalId": terminal_id,
        "merchantId": merchant_id,
        "transactionDate": outcome.get("transactionDate"),
        "transactionTime": outcome.get("transactionTime"),
        "amountCents": amount_centimes,
    }
