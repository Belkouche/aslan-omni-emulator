#!/usr/bin/env python3
"""
Aslan Omni Terminal Emulator
============================
Behaves like a real Aslan Omni terminal (app v1.3.5) on your LAN — UDP discovery
on 8481, HTTP API on 8080 with PIN pairing and OMNI-TOKEN signed requests — and,
with --relay, like a cloud-onboarded device driven by the Aslan Omni cloud API.

Usage:
    python3 omni_emulator.py                          # LAN terminal, approve all
    python3 omni_emulator.py --mode decline           # every payment RC=100
    python3 omni_emulator.py --mode error --code insufficient_funds
    python3 omni_emulator.py --mode cancel            # customer cancels (RC=099)
    python3 omni_emulator.py --mode timeout --timeout-after 5
    python3 omni_emulator.py --mode reversal_decline --code 909
    python3 omni_emulator.py --mode interactive       # prompt per payment
    python3 omni_emulator.py --delay 3                # 3 s of simulated card time
    python3 omni_emulator.py --relay                  # LAN + cloud device (staging)
    python3 omni_emulator.py --no-lan --relay         # cloud device only
    python3 omni_emulator.py --selfcheck              # verify the crypto, then exit

Supported modes:
    approve           Payments approved, reversals succeed (default)
    decline           Payments declined RC=100 (do not honour)
    error             Payments declined with --code (name or number)
    cancel            Payments cancelled by the customer (RC=099)
    timeout           Payments wait --timeout-after s (default 90) then time out
    reversal_decline  Payments approved, reversals declined with --code (default 909)
    reversal_timeout  Payments approved, reversals wait --timeout-after s then fail
    interactive       Prompt the operator per payment; auto-approve after 120 s

Magic amounts (override --mode for payments, LAN and cloud):
    amountCents ending in 00 → approved      05 → declined RC=005
                          08 → cancelled     51 → timeout (answered at once)

Named scenarios for --code:
    approved, insufficient_funds, expired_card, wrong_pin, pin_attempts_exceeded,
    suspected_fraud, do_not_honour, card_not_active, transaction_not_allowed,
    exceeds_limits, invalid_cvv, cancelled, already_cancelled, system_down,
    issuer_unavailable, server_error, record_not_found

Console commands (type + Enter while running):
    p    request a new cloud pairing code (--relay)

Fidelity notes (terminal main f8f74dd, cloud API main 5c34b1d):
    The emulator follows the terminal, not the SDKs: no /reverse alias (404),
    /admin/pos returns createdAt (epoch seconds) and no pairedAt, unknown routes
    are 404 with an empty body, malformed or incomplete JSON is 500
    {"error":"internal error"}. JSON is Gson-shaped: compact, nulls omitted,
    '=' '<' '>' '&' "'" escaped as \\u00XX.
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import random
import re
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("omni-emulator")

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION               = "1.3.5"      # BuildConfig.VERSION_NAME of the emulated release
DEFAULT_MODEL         = "P3"
HTTP_PORT             = 8080
UDP_PORT              = 8481
PAYMENT_TIMEOUT_SEC   = 90           # NapsPay app2app wait before a payment times out
TS_TOLERANCE_SEC      = 300          # OMNI-TOKEN timestamp window (±5 min)
SESSION_TTL_SEC       = 120          # pairing session lifetime
PIN_DIGITS            = 6
PIN_MAX_ATTEMPTS      = 5            # wrong PINs before a session locks
RATE_LIMIT_MAX        = 5            # per IP, shared by /pair/request + /pair/confirm
RATE_LIMIT_WINDOW_SEC = 60
CONFIRM_GLOBAL_MAX    = 15           # /pair/confirm across all IPs per window
BEACON_INTERVAL_SEC   = 30
STALE_PENDING_SEC     = 120          # pending rows older than this become timeout at start
INTERACTIVE_TIMEOUT_SEC = 120
DEFAULT_CODE          = "909"
DISCOVERY_PREFIX      = "OMNI-DISC:"
BEACON_PREFIX         = "OMNI-BEACON:"

MASKED_CARD = "516794******3315"
CARD_SCHEME = "MASTERCARD"

CLOUD_BASE           = "https://staging-api.aslanpay.ma"
CLAIM_POLL_SEC       = 3
SSE_BACKOFF_BASE_SEC = 3
SSE_BACKOFF_MAX_SEC  = 60
# Cloudflare (in front of staging/prod) rejects the default "Python-urllib" UA.
USER_AGENT = f"AslanOmniEmulator/{VERSION} (device)"

STATE_DIR          = os.path.expanduser("~/.aslan-omni-emulator")
DEFAULT_STATE_FILE = os.path.join(STATE_DIR, "terminal.json")
DEFAULT_TOKEN_FILE = os.path.join(STATE_DIR, "device.json")

MODES = ["approve", "decline", "error", "cancel", "timeout",
         "reversal_decline", "reversal_timeout", "interactive"]

# ── ISO 8583 / NAPS response code scenarios ───────────────────────────────────

# Same table as tkpay-naps-emulator (TLV Protocol Specification v2.0 §6).
SCENARIOS: dict[str, tuple[str, str]] = {
    # name                  : (code, label)
    "approved"              : ("000", "Approved"),
    "do_not_honour"         : ("100", "Do not honour"),
    "expired_card"          : ("101", "Card expired"),
    "suspected_fraud"       : ("102", "Fraud suspected"),
    "pin_attempts_exceeded" : ("106", "Allowed PIN tries exceeded"),
    "wrong_pin"             : ("117", "Incorrect PIN"),
    "insufficient_funds"    : ("116", "Insufficient funds"),
    "card_not_active"       : ("118", "Card not registered"),
    "transaction_not_allowed": ("120", "Transaction not permitted at terminal"),
    "exceeds_limits"        : ("121", "Withdrawal limit exceeded"),
    "invalid_cvv"           : ("183", "Invalid CVV"),
    "cancelled"             : ("280", "Alternative amount cancelled"),
    "record_not_found"      : ("302", "Record not found on file"),
    "already_cancelled"     : ("482", "Transaction already cancelled"),
    "system_down"           : ("909", "System failure"),
    "issuer_unavailable"    : ("912", "Card issuer unavailable"),
    "server_error"          : ("995", "Server processing error"),
}

# Ordered list for the interactive decline menu (most common first)
DECLINE_MENU: list[str] = [
    "insufficient_funds",
    "wrong_pin",
    "pin_attempts_exceeded",
    "expired_card",
    "suspected_fraud",
    "do_not_honour",
    "card_not_active",
    "transaction_not_allowed",
    "exceeds_limits",
    "invalid_cvv",
    "system_down",
    "issuer_unavailable",
    "server_error",
]


def resolve_code(code: str) -> str:
    """Resolve a scenario name or raw code string to a 3-digit RC."""
    if code in SCENARIOS:
        return SCENARIOS[code][0]
    return code


def code_label(rc: str) -> str:
    return next((v[1] for v in SCENARIOS.values() if v[0] == rc), rc)


# ── Magic amounts ─────────────────────────────────────────────────────────────

def magic_outcome(amount_cents: int) -> str | None:
    """Outcome forced by the amount's last two digits, or None (falls through to --mode)."""
    return {0: "approved", 5: "declined", 8: "cancelled", 51: "timeout"}.get(amount_cents % 100)


# ── JSON helpers ──────────────────────────────────────────────────────────────

def drop_nulls(obj):
    """Gson's default: null map values are not serialized."""
    if isinstance(obj, dict):
        return {k: drop_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [drop_nulls(v) for v in obj]
    return obj


# Gson escapes these by default (HTML-safe output); they only ever occur inside strings.
_GSON_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "=": "\\u003d",
                 "'": "\\u0027", " ": "\\u2028", " ": "\\u2029"}


def gson_bytes(obj) -> bytes:
    """Serialize like the terminal's Gson: compact, nulls dropped, HTML chars escaped."""
    text = json.dumps(drop_nulls(obj), separators=(",", ":"), ensure_ascii=False)
    for ch, esc in _GSON_ESCAPES.items():
        text = text.replace(ch, esc)
    return text.encode("utf-8")


def android_json_bytes(obj: dict) -> bytes:
    """Serialize like Android's org.json JSONObject.toString(): compact, '/' escaped."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).replace("/", "\\/").encode("utf-8")


def str_field(req: dict, name: str, required: bool = True) -> str | None:
    """Read a String DTO field the way Gson does (numbers/booleans coerce to text)."""
    v = req.get(name)
    if v is None:
        if required:
            raise ValueError(f"missing {name}")
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, str):
        return v
    raise ValueError(f"{name} is not a string")


def long_field(req: dict, name: str) -> int:
    """Read a Long DTO field the way Gson does (integral numbers or numeric strings)."""
    v = req.get(name)
    if isinstance(v, bool) or v is None:
        raise ValueError(f"missing {name}")
    if isinstance(v, str):
        v = float(v) if re.fullmatch(r"[+-]?\d+\.\d*", v.strip()) else int(v.strip())
    if isinstance(v, float):
        if not v.is_integer():
            raise ValueError(f"{name} is not integral")
        v = int(v)
    if not isinstance(v, int):
        raise ValueError(f"{name} is not a number")
    return v


# ── Crypto ────────────────────────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# RSA-OAEP-SHA256 encrypt (stdlib has no RSA). The terminal returns the pairing
# tokenSecret encrypted to the POS's ephemeral SPKI public key; this must match
# RSA/ECB/OAEPWithSHA-256AndMGF1Padding so WebCrypto / .NET can decrypt it.

def _der_len(data: bytes, i: int) -> tuple[int, int]:
    """Read a DER length at offset i; return (length, next_offset)."""
    b = data[i]; i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    return int.from_bytes(data[i:i + n], "big"), i + n


def _parse_spki_rsa(spki: bytes) -> tuple[int, int]:
    """Extract (modulus n, public exponent e) from an SPKI/DER RSA public key."""
    # SPKI: SEQ { SEQ { OID rsaEncryption, NULL }, BIT STRING { RSAPublicKey } }
    i = 0
    if spki[i] != 0x30: raise ValueError("not an SPKI SEQUENCE")
    _, i = _der_len(spki, i + 1)
    if spki[i] != 0x30: raise ValueError("no AlgorithmIdentifier")
    alg_len, j = _der_len(spki, i + 1)
    i = j + alg_len
    if spki[i] != 0x03: raise ValueError("no BIT STRING")
    _, i = _der_len(spki, i + 1)
    if spki[i] != 0x00: raise ValueError("bad unused-bits byte")
    i += 1
    if spki[i] != 0x30: raise ValueError("no RSAPublicKey")
    _, i = _der_len(spki, i + 1)
    if spki[i] != 0x02: raise ValueError("no modulus")
    n_len, i = _der_len(spki, i + 1)
    n = int.from_bytes(spki[i:i + n_len], "big"); i += n_len
    if spki[i] != 0x02: raise ValueError("no exponent")
    e_len, i = _der_len(spki, i + 1)
    return n, int.from_bytes(spki[i:i + e_len], "big")


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_oaep_encrypt_b64(spki_b64: str, message: bytes) -> str:
    """RSA-OAEP-SHA256 encrypt `message` to the SPKI public key; return base64."""
    n, e = _parse_spki_rsa(base64.b64decode(spki_b64, validate=True))
    k = (n.bit_length() + 7) // 8
    h_len = 32
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("message too long for RSA-OAEP")
    db = hashlib.sha256(b"").digest() + b"\x00" * (k - len(message) - 2 * h_len - 2) + b"\x01" + message
    seed = secrets.token_bytes(h_len)
    masked_db = bytes(a ^ b for a, b in zip(db, _mgf1_sha256(seed, k - h_len - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1_sha256(masked_db, h_len)))
    c = pow(int.from_bytes(b"\x00" + masked_seed + masked_db, "big"), e, n)
    return base64.b64encode(c.to_bytes(k, "big")).decode()


def lan_signature(token_hmac_hex: str, token_id: str, ts: str, method: str, path: str, body: bytes) -> str:
    """LAN OMNI-TOKEN signature. Key = bytes of tokenHmac, where tokenHmac = HMAC(secret, tokenId)."""
    msg = f"{token_id}:{ts}:{method}:{path}:{sha256_hex(body)}"
    return hmac_hex(bytes.fromhex(token_hmac_hex), msg.encode())


def device_auth_header(device_token: str, method: str, path: str, body: bytes) -> str:
    """Cloud device OMNI-TOKEN header. Key = utf8(deviceToken); tokenId = deviceToken."""
    ts = str(int(time.time()))
    msg = f"{device_token}:{ts}:{method}:{path}:{sha256_hex(body)}"
    return f"OMNI-TOKEN tokenId={device_token},ts={ts},sig={hmac_hex(device_token.encode(), msg.encode())}"


# ── Console ───────────────────────────────────────────────────────────────────

QUIET = False   # tests silence boxes and prompts


def say(text: str = "") -> None:
    if not QUIET:
        print(text, flush=True)


def boxed(title: str, lines: list[str]) -> str:
    w = max([len(title) + 2] + [len(l) + 4 for l in lines] + [44])
    out = [f"  ┌{'─' * w}┐", f"  │{title:^{w}}│", f"  ├{'─' * w}┤"]
    out += [f"  │  {l:<{w - 2}}│" for l in lines]
    out.append(f"  └{'─' * w}┘")
    return "\n".join(out)


def lan_ip() -> str:
    """Best-effort primary LAN address (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


# ── Interactive decision prompt ───────────────────────────────────────────────

_prompt_lock   = threading.Lock()
_prompt_active = threading.Event()
_stdin_queue: queue.Queue[str] = queue.Queue()
CONSOLE_COMMANDS: dict = {}     # "p" → callable, registered by main()


def _stdin_reader() -> None:
    """Route stdin lines: to the open prompt if there is one, else to console commands."""
    while True:
        try:
            line = input().strip().lower()
        except EOFError:
            _stdin_queue.put("a")
            break
        if _prompt_active.is_set():
            _stdin_queue.put(line)
        elif line in CONSOLE_COMMANDS:
            threading.Thread(target=CONSOLE_COMMANDS[line], daemon=True).start()
        elif line:
            say(f"  Unknown command {line!r}" + ("  (p = new cloud pairing code)" if CONSOLE_COMMANDS else ""))


def ask_operator(source: str, ref: str, amount_cents: int, timeout: float) -> tuple[str, str | None]:
    """
    Prompt the operator for one payment. Returns (choice, rc) where choice is
    approve / decline / cancel / timeout. One prompt at a time.
    """
    with _prompt_lock:
        say(f"\n  ┌── Payment from {source} ──────────────────────────")
        say(f"  │  Ref    : {ref}")
        say(f"  │  Amount : {amount_cents / 100:.2f} MAD")
        say(f"  │  Card   : {MASKED_CARD}")
        say("  ├─────────────────────────────────────────────────")
        say("  │  [a] Approve")
        for i, name in enumerate(DECLINE_MENU, 1):
            code, label = SCENARIOS[name]
            say(f"  │  [{i:2d}] Decline — {label} ({code})")
        say("  │  [c] Customer cancels (099)")
        say("  │  [t] Timeout (no answer from NapsPay)")
        say("  └─────────────────────────────────────────────────")
        if not QUIET:
            print("  Choice → ", end="", flush=True)
        _prompt_active.set()
        try:
            while True:
                try:
                    answer = _stdin_queue.get(timeout=timeout)
                except queue.Empty:
                    say("(timeout → auto-approve)")
                    return "approve", None
                if answer in ("a", "approve", "y", "yes", ""):
                    say("  → APPROVED")
                    return "approve", None
                if answer in ("c", "cancel"):
                    say("  → CANCELLED (099)")
                    return "cancel", None
                if answer in ("t", "timeout"):
                    say("  → TIMEOUT")
                    return "timeout", None
                if answer.isdigit() and 1 <= int(answer) <= len(DECLINE_MENU) and len(answer) < 3:
                    code, label = SCENARIOS[DECLINE_MENU[int(answer) - 1]]
                    say(f"  → DECLINED ({label} — {code})")
                    return "decline", code
                resolved = resolve_code(answer)
                if resolved != answer or (len(resolved) == 3 and resolved.isdigit()):
                    say(f"  → DECLINED ({code_label(resolved)} — {resolved})")
                    return "decline", resolved
                if not QUIET:
                    print(f"  Unknown input {answer!r} — type a, c, t, a number, or a code: ", end="", flush=True)
        finally:
            _prompt_active.clear()


# ── Outcome engine ────────────────────────────────────────────────────────────

@dataclass
class Config:
    mode: str = "approve"
    code: str = DEFAULT_CODE
    delay: float = 0.0                      # simulated card time before any outcome
    timeout_after: float = PAYMENT_TIMEOUT_SEC
    interactive_timeout: float = INTERACTIVE_TIMEOUT_SEC
    terminal_id: str = "00000001"
    merchant_id: str = "000000000001"
    serial: str = f"EMU-{socket.gethostname().split('.')[0]}"
    model: str = DEFAULT_MODEL
    host: str = "0.0.0.0"
    lan_port: int = HTTP_PORT
    udp_port: int = UDP_PORT
    lan: bool = True
    beacon: bool = True
    state_file: str = DEFAULT_STATE_FILE
    fresh: bool = False


def generate_stan() -> str: return f"{random.randint(1, 999999):06d}"
def generate_auth() -> str: return f"{random.randint(100000, 999999)}"


class OutcomeEngine:
    """
    Stands in for NapsPay. Returns a NapsPay-style result dict whose "status" is
    approved / declined / cancelled / timeout; callers map it (LAN reversal:
    approved → "reversed", cloud: see result_payload).
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._inflight: set[str] = set()
        self._lock = threading.Lock()

    def _approved(self) -> dict:
        now = datetime.now()
        return {
            "status": "approved", "responseCode": "000",
            "authNumber": generate_auth(), "stan": generate_stan(),
            "cardNumber": MASKED_CARD, "cardScheme": CARD_SCHEME,
            "terminalId": self.cfg.terminal_id, "merchantId": self.cfg.merchant_id,
            "transactionDate": now.strftime("%d/%m/%Y"), "transactionTime": now.strftime("%H:%M:%S"),
            "transactionNumber": generate_stan(),
            # No rrn: NapsPay app2app never fills it.
        }

    @staticmethod
    def _declined(rc: str) -> dict:
        return {"status": "declined", "responseCode": rc}

    def _timeout(self, wait: bool) -> dict:
        if wait and self.cfg.timeout_after > 0:
            time.sleep(self.cfg.timeout_after)
        return {"status": "timeout"}

    def pay(self, ref: str, amount_cents: int, source: str) -> dict:
        with self._lock:
            if ref in self._inflight:       # NapsPayBridge: same ref already on screen
                return self._declined("DUPLICATE")
            self._inflight.add(ref)
        try:
            if self.cfg.delay > 0:
                time.sleep(self.cfg.delay)
            forced = magic_outcome(amount_cents)
            if forced == "approved":  return self._approved()
            if forced == "declined":  return self._declined("005")
            if forced == "cancelled": return {"status": "cancelled", "responseCode": "099"}
            if forced == "timeout":   return self._timeout(wait=False)

            mode = self.cfg.mode
            if mode == "decline":
                return self._declined("100")
            if mode == "error":
                return self._declined(resolve_code(self.cfg.code))
            if mode == "cancel":
                return {"status": "cancelled", "responseCode": "099"}
            if mode == "timeout":
                return self._timeout(wait=True)
            if mode == "interactive":
                choice, rc = ask_operator(source, ref, amount_cents, self.cfg.interactive_timeout)
                if choice == "decline": return self._declined(rc)
                if choice == "cancel":  return {"status": "cancelled", "responseCode": "099"}
                if choice == "timeout": return self._timeout(wait=False)
            return self._approved()
        finally:
            with self._lock:
                self._inflight.discard(ref)

    def reversal(self, ref: str, stan: str) -> dict:
        if self.cfg.delay > 0:
            time.sleep(self.cfg.delay)
        if self.cfg.mode == "reversal_decline":
            return self._declined(resolve_code(self.cfg.code))
        if self.cfg.mode == "reversal_timeout":
            return self._timeout(wait=True)
        return self._approved()


def describe(result: dict) -> str:
    """One-line outcome for the request log."""
    parts = [result["status"]]
    if result.get("responseCode"):
        parts.append(f"RC={result['responseCode']}")
    if result.get("stan"):
        parts.append(f"STAN={result['stan']}")
    return " ".join(parts)


# ── Terminal state (tokens, transactions, keys) ───────────────────────────────

class PairRateLimiter:
    """Fixed-window limiter: per IP (pair request + confirm) and global (confirm only)."""

    def __init__(self) -> None:
        self.max = RATE_LIMIT_MAX
        self.window = RATE_LIMIT_WINDOW_SEC
        self.global_max = CONFIRM_GLOBAL_MAX
        self._buckets: dict[str, list] = {}
        self._global = [0, 0.0]
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            bucket = self._buckets.setdefault(ip, [0, now])
            if now - bucket[1] >= self.window:
                bucket[:] = [0, now]
            if bucket[0] >= self.max:
                return False
            bucket[0] += 1
            return True

    def allow_global_confirm(self) -> bool:
        with self._lock:
            now = time.time()
            if now - self._global[1] >= self.window:
                self._global[:] = [0, now]
            if self._global[0] >= self.global_max:
                return False
            self._global[0] += 1
            return True


class TerminalState:
    """
    What the terminal keeps in Room + settings: paired POS tokens, transactions,
    admin key and discovery key — persisted as one JSON file. Pairing sessions
    live in memory (they expire after 120 s anyway).
    """

    def __init__(self, path: str, fresh: bool = False) -> None:
        self.path = path
        self.lock = threading.RLock()
        data = {} if fresh else self._load()
        self.admin_key: str = data.get("adminKey") or secrets.token_urlsafe(24)
        self.discovery_key = bytes.fromhex(data.get("discoveryKey") or secrets.token_hex(32))
        self.tokens: dict[str, dict] = data.get("tokens", {})
        self.transactions: dict[str, dict] = data.get("transactions", {})
        self.sessions: dict[str, dict] = {}
        self.limiter = PairRateLimiter()
        self.last_pin: str | None = None    # test hook: the PIN shown on screen
        reaped = self.reap_stuck_pending()
        if reaped:
            log.info(f"marked {reaped} stale pending transaction(s) as timeout")
        self.save()

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"ignoring unreadable state file {self.path}: {e}")
            return {}

    def save(self) -> None:
        with self.lock:
            data = {"adminKey": self.admin_key, "discoveryKey": self.discovery_key.hex(),
                    "tokens": self.tokens, "transactions": self.transactions}
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(self.path)), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1)
            os.replace(tmp, self.path)

    def reap_stuck_pending(self, older_than: float = STALE_PENDING_SEC) -> int:
        """A payment killed mid-flight must not wedge its ref at 409 forever."""
        cutoff_ms = (time.time() - older_than) * 1000
        n = 0
        with self.lock:
            for tx in self.transactions.values():
                if tx["status"] == "pending" and tx.get("createdAt", 0) < cutoff_ms:
                    tx["status"] = "timeout"
                    n += 1
        return n

    def record(self, tx: dict) -> None:
        with self.lock:
            self.transactions[tx["ref"]] = tx
            self.save()


def completed_tx(ref: str, amount_cents: int, status: str, result: dict, req: dict | None,
                 pos_id: str | None, created_at_ms: int) -> dict:
    """TransactionRecorder.completed(): the row stored for a finished payment."""
    req = req or {}
    return {
        "ref": ref, "status": status, "amountCents": amount_cents,
        "cashierId": req.get("cashierId"), "tillId": req.get("tillId"),
        "description": req.get("description"),
        "responseCode": result.get("responseCode"), "authNumber": result.get("authNumber"),
        "stan": result.get("stan"), "rrn": result.get("rrn"),
        "cardNumber": result.get("cardNumber"), "cardScheme": result.get("cardScheme"),
        "terminalId": result.get("terminalId"), "merchantId": result.get("merchantId"),
        "txDate": result.get("transactionDate"), "txTime": result.get("transactionTime"),
        "posId": pos_id, "createdAt": created_at_ms, "completedAt": int(time.time() * 1000),
    }


def tx_response(tx: dict) -> dict:
    """PayResult JSON returned by LAN /pay (TransactionEntity.toResponse)."""
    return {
        "status": tx["status"], "ref": tx["ref"], "responseCode": tx.get("responseCode"),
        "authNumber": tx.get("authNumber"), "stan": tx.get("stan"), "rrn": tx.get("rrn"),
        "cardNumber": tx.get("cardNumber"), "cardScheme": tx.get("cardScheme"),
        "terminalId": tx.get("terminalId"), "merchantId": tx.get("merchantId"),
        "transactionDate": tx.get("txDate"), "transactionTime": tx.get("txTime"),
        "amountCents": tx["amountCents"],
    }


# ── LAN HTTP API ──────────────────────────────────────────────────────────────

@dataclass
class Reply:
    status: int
    body: dict | None = None     # None → empty body
    detail: str = ""             # request summary for the log line
    outcome: str = ""            # result summary for the log line


def err(status: int, message: str, detail: str = "") -> Reply:
    return Reply(status, {"error": message}, detail, f"{status} {message}")


class LanApi:
    """The terminal's Ktor routes, transport-free so they can be self-checked."""

    def __init__(self, state: TerminalState, engine: OutcomeEngine, cfg: Config) -> None:
        self.state = state
        self.engine = engine
        self.cfg = cfg

    def handle(self, method: str, raw_path: str, headers, body: bytes, ip: str) -> Reply:
        path = urllib.parse.urlsplit(raw_path).path
        try:
            route = self._route(method, path)
            if route is None:
                return Reply(404, None, "", "404 (no such route)")
            fn, args = route
            return fn(headers, body, ip, path, *args)
        except Exception as e:      # StatusPages: any uncaught exception
            log.debug(f"internal error: {e!r}")
            return err(500, "internal error")

    def _route(self, method: str, path: str):
        table = {
            ("GET", "/health"): self.health,
            ("POST", "/pay"): self.pay,
            ("POST", "/reversal"): self.reversal,
            ("GET", "/admin/pos"): self.list_pos,
            ("POST", "/admin/reversal"): self.admin_reversal,
            ("POST", "/pair/request"): self.pair_request,
            ("POST", "/pair/confirm"): self.pair_confirm,
        }
        if (method, path) in table:
            return table[(method, path)], ()
        m = re.fullmatch(r"/admin/pos/([^/]+)", path)
        if method == "DELETE" and m:
            return self.revoke_pos, (urllib.parse.unquote(m.group(1)),)
        return None

    # ── Auth ──────────────────────────────────────────────────────────────────

    def authenticate(self, headers, method: str, path: str, body: bytes) -> tuple[dict | None, Reply | None]:
        """Verify OMNI-TOKEN; returns (token, None) or (None, 401 reply). Same check order as the terminal."""
        header = headers.get("Authorization")
        if header is None or not header.startswith("OMNI-TOKEN "):
            return None, err(401, "missing or invalid Authorization")
        parts = {}
        for seg in header[len("OMNI-TOKEN "):].split(","):
            kv = seg.strip().split("=", 1)
            if len(kv) == 2:
                parts[kv[0]] = kv[1]
        token_id = parts.get("tokenId")
        if token_id is None:
            return None, err(401, "missing tokenId")
        ts = parts.get("ts")
        if ts is None or not re.fullmatch(r"[+-]?\d+", ts):
            return None, err(401, "missing ts")
        sig = parts.get("sig")
        if sig is None:
            return None, err(401, "missing sig")
        if abs(int(time.time()) - int(ts)) > TS_TOLERANCE_SEC:
            return None, err(401, "timestamp out of window")
        token = self.state.tokens.get(token_id)
        if token is None:
            return None, err(401, "unknown token")
        expected = lan_signature(token["tokenHmac"], token_id, ts, method, path, body)
        if not hmac.compare_digest(expected.encode(), sig.encode()):
            return None, err(401, "invalid signature")
        return {**token, "tokenId": token_id}, None

    @staticmethod
    def receive_json(headers, body: bytes) -> dict:
        """call.receive<Dto>() through ContentNegotiation: needs a JSON content type."""
        ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise ValueError(f"unsupported content type {ctype!r}")
        return LanApi.parse_json(body)

    @staticmethod
    def parse_json(body: bytes) -> dict:
        req = json.loads(body.decode("utf-8"))
        if not isinstance(req, dict):
            raise ValueError("body is not an object")
        return req

    # ── Routes ────────────────────────────────────────────────────────────────

    def health(self, headers, body, ip, path) -> Reply:
        return Reply(200, {"status": "ok", "version": VERSION, "napsPay": "installed"})

    def pair_request(self, headers, body, ip, path) -> Reply:
        if not self.state.limiter.allow(ip):
            return err(429, "rate limit exceeded")
        req = self.receive_json(headers, body)
        pos_id, pos_label = str_field(req, "posId"), str_field(req, "posLabel")
        str_field(req, "clientNonce")
        pub_key = str_field(req, "clientPubKey", required=False)
        session_id = str(uuid.uuid4())
        pin = f"{secrets.randbelow(10 ** PIN_DIGITS):0{PIN_DIGITS}d}"
        with self.state.lock:
            self.state.sessions[session_id] = {
                # Salted with the sessionId, as on the terminal.
                "pinHash": sha256_hex((session_id + pin).encode()),
                "posId": pos_id, "posLabel": pos_label, "clientPubKey": pub_key,
                "expiresAt": int(time.time()) + SESSION_TTL_SEC,
                "failedAttempts": 0, "used": False,
            }
            self.state.last_pin = pin
        say("\n" + boxed("PAIRING PIN", [
            f"POS     : {pos_label} ({pos_id})",
            f"PIN     : {pin}",
            f"Expires : {SESSION_TTL_SEC} s",
            "Encrypted secret" if pub_key else "Cleartext secret (no clientPubKey)",
        ]) + "\n")
        return Reply(200, {"sessionId": session_id, "expiresIn": SESSION_TTL_SEC},
                     f"posId={pos_id}", f"200 session={session_id[:8]}")

    def pair_confirm(self, headers, body, ip, path) -> Reply:
        if not (self.state.limiter.allow(ip) and self.state.limiter.allow_global_confirm()):
            return err(429, "rate limit exceeded")
        req = self.receive_json(headers, body)
        session_id, pin = str_field(req, "sessionId"), str_field(req, "pin")
        detail = f"session={session_id[:8]}"
        with self.state.lock:
            s = self.state.sessions.get(session_id)
            if s is None or s["used"] or s["expiresAt"] < int(time.time()):
                return err(400, "invalid or expired session", detail)
            if s["failedAttempts"] >= PIN_MAX_ATTEMPTS:
                s["used"] = True
                return err(400, "invalid or expired session", detail)
            if not hmac.compare_digest(sha256_hex((session_id + pin).encode()), s["pinHash"]):
                s["failedAttempts"] += 1
                return err(400, "wrong pin", detail)
            s["used"] = True

            token_secret = secrets.token_bytes(32)
            token_id = str(uuid.uuid4())
            resp = {"tokenId": token_id, "posId": s["posId"], "terminalModel": self.cfg.model}
            if s["clientPubKey"] is not None:
                try:
                    resp["encryptedTokenSecret"] = rsa_oaep_encrypt_b64(s["clientPubKey"], token_secret)
                except Exception as e:
                    log.debug(f"tokenSecret encryption failed: {e!r}")
                    return err(400, "invalid clientPubKey", detail)
            else:
                resp["tokenSecret"] = token_secret.hex()
            # posId/posLabel come from the session, never from this body.
            self.state.tokens[token_id] = {
                "tokenHmac": hmac_hex(token_secret, token_id.encode()),
                "posId": s["posId"], "posLabel": s["posLabel"], "createdAt": int(time.time()),
            }
            self.state.save()
        say(f"  ✔ Paired {s['posLabel']} ({s['posId']}) — tokenId {token_id}\n")
        return Reply(200, resp, detail, f"200 paired posId={s['posId']} tokenId={token_id[:8]}")

    def pay(self, headers, body, ip, path) -> Reply:
        token, denied = self.authenticate(headers, "POST", path, body)
        if denied:
            return denied
        req = self.parse_json(body)
        ref, amount = str_field(req, "ref"), long_field(req, "amountCents")
        for opt in ("cashierId", "tillId", "description"):
            str_field(req, opt, required=False)
        detail = f"ref={ref} amount={amount}"
        now_ms = int(time.time() * 1000)

        with self.state.lock:
            cached = self.state.transactions.get(ref)
            if cached is not None:
                if cached["status"] in ("approved", "reversed"):
                    return Reply(200, tx_response(cached), detail, f"cached {describe(cached)}")
                if cached["status"] == "pending":
                    return err(409, "ref already in progress", detail)
                # timeout / declined / cancelled: no money moved → charge again, same ref
                cached["status"], cached["createdAt"] = "pending", now_ms
            else:
                self.state.transactions[ref] = {
                    "ref": ref, "status": "pending", "amountCents": amount,
                    "cashierId": req.get("cashierId"), "tillId": req.get("tillId"),
                    "description": req.get("description"), "posId": token["posId"], "createdAt": now_ms,
                }
            self.state.save()

        result = self.engine.pay(ref, amount, source=f"{ip} ({token['posLabel']})")
        tx = completed_tx(ref, amount, result["status"], result, req, token["posId"], now_ms)
        self.state.record(tx)
        return Reply(200, tx_response(tx), detail, describe(result))

    def reversal(self, headers, body, ip, path) -> Reply:
        token, denied = self.authenticate(headers, "POST", path, body)
        if denied:
            return denied
        req = self.parse_json(body)
        ref, original_ref, stan = str_field(req, "ref"), str_field(req, "originalRef"), str_field(req, "stan")
        detail = f"ref={ref} originalRef={original_ref} stan={stan}"
        original = self.state.transactions.get(original_ref)
        # A POS may only reverse its own sale, with the matching STAN.
        if original is None or original.get("posId") != token["posId"] or original.get("stan") != stan:
            return err(403, "not authorized to reverse this transaction", detail)
        result = self.engine.reversal(ref, stan)
        status = "reversed" if result["status"] == "approved" else "declined"
        return Reply(200, {"status": status, "ref": ref, "responseCode": result.get("responseCode")},
                     detail, f"{status}" + (f" RC={result['responseCode']}" if result.get("responseCode") else ""))

    def admin_reversal(self, headers, body, ip, path) -> Reply:
        key = headers.get("X-Admin-Key")
        if key is None or not hmac.compare_digest(key.encode(), self.state.admin_key.encode()):
            return err(401, "invalid admin key")
        req = self.parse_json(body)
        original_ref, reversal_ref = str_field(req, "originalRef"), str_field(req, "reversalRef")
        detail = f"originalRef={original_ref} reversalRef={reversal_ref}"
        with self.state.lock:
            original = self.state.transactions.get(original_ref)
            if original is None:
                return err(404, "transaction not found", detail)
            if original["status"] == "pending":
                original["status"] = "cancelled"
                self.state.save()
                return Reply(200, {"status": "cancelled", "ref": original_ref, "note": "pending cleared locally"},
                             detail, "cancelled (pending cleared locally)")
            stan = original.get("stan")
        if stan is None:
            return err(422, "no STAN on record — cannot reverse", detail)
        result = self.engine.reversal(reversal_ref, stan)
        status = "reversed" if result["status"] == "approved" else "declined"
        return Reply(200, {"status": status, "ref": reversal_ref, "responseCode": result.get("responseCode")},
                     detail, status)

    def list_pos(self, headers, body, ip, path) -> Reply:
        token, denied = self.authenticate(headers, "GET", path, b"")
        if denied:
            return denied
        # Each POS only ever sees itself.
        return Reply(200, {"pos": [{"tokenId": token["tokenId"], "posId": token["posId"],
                                    "posLabel": token["posLabel"], "createdAt": token["createdAt"]}]},
                     f"posId={token['posId']}", "200")

    def revoke_pos(self, headers, body, ip, path, token_id: str) -> Reply:
        caller, denied = self.authenticate(headers, "DELETE", path, b"")
        if denied:
            return denied
        if token_id != caller["tokenId"]:
            return err(403, "forbidden", f"tokenId={token_id}")
        with self.state.lock:
            if self.state.tokens.pop(token_id, None) is None:
                return err(404, "token not found", f"tokenId={token_id}")
            self.state.save()
        return Reply(204, None, f"tokenId={token_id}", "204 revoked")


def make_http_server(host: str, port: int, api: LanApi) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Ktor/emulated"
        sys_version = ""

        def log_message(self, *a) -> None:
            pass    # one line per request is logged by _dispatch

        def _dispatch(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n > 0 else b""
            ip = self.client_address[0]
            reply = api.handle(self.command, self.path, self.headers, body, ip)

            payload = gson_bytes(reply.body) if reply.body is not None else b""
            self.send_response(reply.status)
            if reply.body is not None:
                self.send_header("Content-Type", "application/json; charset=UTF-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)

            path = urllib.parse.urlsplit(self.path).path
            detail = f" {reply.detail}" if reply.detail else ""
            log.info(f"[{ip}] {self.command} {path}{detail} → {reply.outcome or reply.status}")
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"[{ip}]   request : {body.decode('utf-8', 'replace') or '(empty)'}")
                log.debug(f"[{ip}]   response: {payload.decode('utf-8', 'replace') or '(empty)'}")

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = _dispatch

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


# ── UDP discovery ─────────────────────────────────────────────────────────────

def discovery_reply(state: TerminalState, cfg: Config, nonce: str) -> bytes:
    return gson_bytes({"device": cfg.serial, "model": cfg.model, "version": VERSION,
                       "hmac": hmac_hex(state.discovery_key, nonce.encode())})


def run_discovery(sock: socket.socket, state: TerminalState, cfg: Config, stop: threading.Event) -> None:
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(256)
        except socket.timeout:
            continue
        except OSError:
            break
        msg = data.decode("utf-8", "replace")
        if msg.startswith(DISCOVERY_PREFIX):
            nonce = msg[len(DISCOVERY_PREFIX):].strip()
            try:
                sock.sendto(discovery_reply(state, cfg, nonce), addr)
                log.info(f"[{addr[0]}] UDP {DISCOVERY_PREFIX} nonce={nonce[:16]} → identity")
            except OSError as e:
                log.warning(f"[{addr[0]}] discovery reply failed: {e}")


def run_beacon(cfg: Config, port: int, stop: threading.Event) -> None:
    msg = (BEACON_PREFIX + gson_bytes({"device": cfg.serial, "model": cfg.model,
                                       "version": VERSION}).decode()).encode()
    while not stop.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(msg, ("255.255.255.255", port))
        except OSError as e:
            log.debug(f"beacon send failed: {e}")
        stop.wait(BEACON_INTERVAL_SEC)


# ── Emulator (LAN half) ───────────────────────────────────────────────────────

class Emulator:
    """State + outcome engine, plus (unless cfg.lan is False) the HTTP and UDP listeners."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.state = TerminalState(cfg.state_file, fresh=cfg.fresh)
        self.engine = OutcomeEngine(cfg)
        self.api = LanApi(self.state, self.engine, cfg)
        self.stop_event = threading.Event()
        self.http: ThreadingHTTPServer | None = None
        self.udp: socket.socket | None = None
        self.lan_port = cfg.lan_port
        self.udp_port = cfg.udp_port

    def start(self) -> None:
        if not self.cfg.lan:
            return
        self.http = make_http_server(self.cfg.host, self.cfg.lan_port, self.api)
        self.lan_port = self.http.server_address[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((self.cfg.host, self.cfg.udp_port))
        self.udp_port = self.udp.getsockname()[1]
        threading.Thread(target=self.http.serve_forever, args=(0.1,), daemon=True).start()
        threading.Thread(target=run_discovery, args=(self.udp, self.state, self.cfg, self.stop_event),
                         daemon=True).start()
        if self.cfg.beacon:
            threading.Thread(target=run_beacon, args=(self.cfg, self.udp_port, self.stop_event),
                             daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.http:
            self.http.shutdown()
            self.http.server_close()
        if self.udp:
            self.udp.close()


# ── Cloud device: token acquisition ───────────────────────────────────────────

def api_root(base: str) -> str:
    """Requests go to BASE/omni/...; nginx strips /omni, so signatures cover the bare path."""
    base = base.rstrip("/")
    return base if base.endswith("/omni") else base + "/omni"


def _cloud_json(root: str, method: str, path: str, body_obj: dict | None = None) -> dict:
    """Unauthenticated cloud call (claim, claim status, demo token)."""
    body = json.dumps(body_obj, separators=(",", ":")).encode() if body_obj is not None else None
    headers = {"User-Agent": USER_AGENT}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(root + path, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def save_device_token(path: str, rec: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)


def load_device_token(path: str, base: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    cached = rec.get("cloudBase")
    return rec if rec.get("deviceToken") and cached and api_root(cached) == api_root(base) else None


def reset_device_token(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False


def fetch_demo_token(root: str) -> dict | None:
    """Shared staging demo terminal; None if the server has none configured (404) or on error."""
    try:
        rec = _cloud_json(root, "GET", "/devices/demo-token")
        return rec if rec.get("deviceToken") else None
    except urllib.error.HTTPError as e:
        if e.code != 404:
            log.warning(f"[cloud] demo-token fetch failed: HTTP {e.code}")
    except Exception as e:
        log.warning(f"[cloud] demo-token fetch failed: {e}")
    return None


def claim_device(root: str, cfg: Config, poll_sec: float = CLAIM_POLL_SEC) -> dict:
    """Claim flow: POST /devices/claim, show the URL, poll status until activated."""
    while True:
        resp = _cloud_json(root, "POST", "/devices/claim",
                           {"serialNumber": cfg.serial, "model": cfg.model, "appVersion": VERSION})
        claim_url = resp.get("claimUrl", "")
        claim_uuid = resp.get("uuid") or claim_url.rsplit("/", 1)[-1]
        say("\n" + boxed("ACTIVATE THIS DEVICE", [f"Open : {claim_url}",
                                                  "Then activate it in the dashboard."]) + "\n")
        log.info("[cloud] waiting for activation…")
        while True:
            time.sleep(poll_sec)
            try:
                status = _cloud_json(root, "GET", f"/devices/claim/{claim_uuid}/status")
            except urllib.error.HTTPError as e:
                if e.code in (404, 410):
                    log.warning("[cloud] claim expired — starting a new claim")
                    break
                continue
            except Exception:
                continue    # network hiccup: keep polling
            if status.get("status") == "activated":
                if status.get("deviceToken"):
                    log.info("[cloud] activated")
                    return status
                log.warning("[cloud] activated without a token (already delivered?) — starting a new claim")
                break


def acquire_device_token(base: str, cfg: Config, token_file: str, explicit: str | None = None,
                         save: bool = False, poll_sec: float = CLAIM_POLL_SEC) -> str:
    """explicit --device-token → cached file → shared demo terminal → claim flow."""
    root = api_root(base)
    if explicit:
        if save:
            save_device_token(token_file, {"deviceToken": explicit, "cloudBase": base})
        return explicit
    cached = load_device_token(token_file, base)
    if cached:
        log.info(f"[cloud] using cached device token from {token_file}")
        return cached["deviceToken"]
    demo = fetch_demo_token(root)
    if demo:
        save_device_token(token_file, {"deviceToken": demo["deviceToken"], "merchantId": demo.get("merchantId"),
                                       "merchantName": demo.get("merchantName"), "cloudBase": base})
        log.info(f"[cloud] using shared demo terminal ({demo.get('merchantName')}) — token cached")
        return demo["deviceToken"]
    log.info("[cloud] no device token — starting claim")
    status = claim_device(root, cfg, poll_sec)
    save_device_token(token_file, {"deviceToken": status["deviceToken"], "merchantId": status.get("merchantId"),
                                   "merchantName": status.get("merchantName"), "cloudBase": base})
    return status["deviceToken"]


# ── Cloud device: SSE relay ───────────────────────────────────────────────────

def sse_events(resp):
    """
    Yield (event, data) from an SSE response as bytes arrive. read1() is used
    because buffered readline() can hold lines back waiting to fill its buffer.
    """
    buf, event, data = b"", None, []
    while True:
        chunk = resp.read1(4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").rstrip("\r")
            if line == "":
                if data:
                    yield event or "message", "\n".join(data)
                event, data = None, []
            elif line.startswith(":"):
                continue
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))


def result_payload(result: dict, is_reversal: bool) -> dict:
    """Body of POST /cloud/pay/{commandId}/result (CloudSyncManager.resultPayload)."""
    s = result["status"]
    status = ("reversed" if is_reversal else "approved") if s == "approved" else s
    keys = [("responseCode", "responseCode"), ("authNumber", "authNumber"), ("stan", "stan"),
            ("rrn", "rrn"), ("cardNumber", "cardNumber"), ("cardScheme", "cardScheme"),
            ("txDate", "transactionDate"), ("txTime", "transactionTime"),
            ("acquirerMerchantId", "merchantId"), ("acquirerTerminalId", "terminalId"),
            ("transactionNumber", "transactionNumber")]
    out = {"status": status}
    out.update({k: result[src] for k, src in keys if result.get(src) is not None})
    return out


def stored_result(tx: dict) -> dict:
    """Rebuild a NapsPay result from a stored row so a re-delivered PayCommand is re-acked, not re-charged."""
    if tx["status"] in ("approved", "reversed"):
        status = "approved"
    elif tx["status"] == "cancelled":
        status = "cancelled"
    else:   # PayResult.isTimeout ⇔ no response code
        status = "declined" if tx.get("responseCode") is not None else "timeout"
    return {"status": status, "responseCode": tx.get("responseCode"), "authNumber": tx.get("authNumber"),
            "stan": tx.get("stan"), "rrn": tx.get("rrn"), "cardNumber": tx.get("cardNumber"),
            "cardScheme": tx.get("cardScheme"), "terminalId": tx.get("terminalId"),
            "merchantId": tx.get("merchantId"), "transactionDate": tx.get("txDate"),
            "transactionTime": tx.get("txTime")}


class CloudDevice:
    """The terminal's CloudSyncManager: SSE in, signed result posts out."""

    def __init__(self, base: str, device_token: str, emu: Emulator,
                 backoff_base: float = SSE_BACKOFF_BASE_SEC, backoff_max: float = SSE_BACKOFF_MAX_SEC) -> None:
        self.base = base
        self.root = api_root(base)
        self.token = device_token
        self.emu = emu
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.stop_event = threading.Event()
        self.connected = threading.Event()
        self.pairing_code: str | None = None
        self._resp = None

    def request(self, method: str, path: str, body: bytes | None = None, stream: bool = False):
        headers = {"Authorization": device_auth_header(self.token, method, path, body or b""),
                   "User-Agent": USER_AGENT}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if stream:
            headers["Accept"] = "text/event-stream"
        req = urllib.request.Request(self.root + path, data=body, method=method, headers=headers)
        return urllib.request.urlopen(req, timeout=None if stream else 30)

    def start(self) -> None:
        threading.Thread(target=self.initiate_pairing, daemon=True).start()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()
        # close() would block on the reader thread's buffer lock; shutting the
        # socket down makes the blocked read1() return instead.
        try:
            self._resp.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

    def initiate_pairing(self) -> None:
        """POST /cloud/pair/initiate — a code the POS enters in pairCloud()."""
        try:
            with self.request("POST", "/cloud/pair/initiate", b"{}") as r:
                obj = json.loads(r.read() or b"{}")
        except Exception as e:
            log.warning(f"[cloud] pair/initiate failed: {e}")
            return
        self.pairing_code = obj.get("pairingCode")
        say("\n" + boxed("CLOUD PAIRING CODE", [
            f"Code    : {self.pairing_code}",
            f"Expires : {obj.get('expiresInSeconds', 120)} s",
            "Enter it in your app's pairCloud(); type p + Enter for a new one.",
        ]) + "\n")

    def _run(self) -> None:
        backoff = self.backoff_base
        while not self.stop_event.is_set():
            try:
                self._resp = self.request("GET", "/cloud/stream", stream=True)
                log.info("[cloud] SSE connected")
                backoff = self.backoff_base
                self.connected.set()
                threading.Thread(target=self.fetch_pending, daemon=True).start()
                for event, data in sse_events(self._resp):
                    if self.stop_event.is_set():
                        break
                    # Own thread per event: the reader must keep draining the stream (and Pings).
                    threading.Thread(target=self._dispatch, args=(event, data), daemon=True).start()
                log.warning("[cloud] SSE stream closed")
            except Exception as e:
                if self.stop_event.is_set():
                    break
                log.warning(f"[cloud] SSE disconnected: {e}")
            finally:
                self.connected.clear()
            if self.stop_event.wait(backoff):
                break
            log.info(f"[cloud] reconnecting (backoff {backoff:g} s)")
            backoff = min(backoff * 2, self.backoff_max)

    def _dispatch(self, event: str, data: str) -> None:
        try:
            if event == "PayCommand":
                self.handle_pay(json.loads(data))
            elif event == "ReverseCommand":
                self.handle_reverse(json.loads(data))
            elif event == "Ping":
                self.ack_ping()
            elif event == "BrandingUpdated":
                log.info("[cloud] BrandingUpdated (logos not emulated)")
            elif event == "PairingRevoked":
                log.info("[cloud] PairingRevoked — a POS pairing was revoked")
        except json.JSONDecodeError:
            log.warning(f"[cloud] malformed {event}: {data[:80]}")
        except Exception as e:
            log.warning(f"[cloud] {event} handling failed: {e!r}")

    def fetch_pending(self) -> None:
        """On (re)connect: a PayCommand queued while we were offline."""
        try:
            with self.request("GET", "/cloud/commands/pending") as r:
                obj = json.loads(r.read() or b"{}")
        except Exception as e:
            log.warning(f"[cloud] fetch pending failed: {e}")
            return
        if isinstance(obj.get("command"), dict):
            self.handle_pay(obj["command"])

    def handle_pay(self, cmd: dict) -> None:
        command_id, ref = str(cmd.get("commandId") or ""), str(cmd.get("ref") or "")
        try:
            amount = long_field(cmd, "amountCents")
        except (ValueError, TypeError):
            amount = -1
        if not command_id or not ref or amount <= 0:
            log.warning(f"[cloud] PayCommand dropped (commandId/ref missing or amount ≤ 0): {cmd}")
            return
        existing = self.emu.state.transactions.get(ref)
        if existing is not None and existing["status"] != "pending":
            log.info(f"[cloud] PayCommand ref={ref} already {existing['status']} — re-posting, no re-charge")
            self.post_result(command_id, stored_result(existing), is_reversal=False)
            return
        result = self.emu.engine.pay(ref, amount, source=f"cloud ({command_id[:8]})")
        self.emu.state.record(completed_tx(ref, amount, result["status"], result, cmd, None,
                                           int(time.time() * 1000)))
        log.info(f"[cloud] PayCommand {command_id} ref={ref} amount={amount} → {describe(result)}")
        self.post_result(command_id, result, is_reversal=False)

    def handle_reverse(self, cmd: dict) -> None:
        command_id, ref, stan = (str(cmd.get(k) or "") for k in ("commandId", "ref", "stan"))
        if not command_id or not ref or not stan:
            log.warning(f"[cloud] ReverseCommand dropped (commandId/ref/stan missing): {cmd}")
            return
        result = self.emu.engine.reversal(ref, stan)
        log.info(f"[cloud] ReverseCommand {command_id} ref={ref} stan={stan} → "
                 f"{result_payload(result, True)['status']}")
        self.post_result(command_id, result, is_reversal=True)

    def ack_ping(self) -> None:
        try:
            self.request("POST", "/cloud/ping", b"{}").close()
        except Exception as e:
            log.warning(f"[cloud] ping ack failed: {e}")

    def post_result(self, command_id: str, result: dict, is_reversal: bool) -> None:
        """One attempt, like the terminal; the cloud's long-poll owns retries."""
        payload = result_payload(result, is_reversal)
        body = android_json_bytes(payload)
        try:
            with self.request("POST", f"/cloud/pay/{command_id}/result", body) as r:
                log.info(f"[cloud] result posted commandId={command_id} status={payload['status']} → HTTP {r.status}")
        except urllib.error.HTTPError as e:
            log.warning(f"[cloud] result post commandId={command_id} → HTTP {e.code}")
        except Exception as e:
            log.warning(f"[cloud] result post commandId={command_id} failed: {e}")
        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"[cloud]   result: {body.decode()}")


# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner(emu: Emulator, cloud_base: str | None) -> None:
    cfg = emu.cfg
    lines = []
    if cfg.lan:
        ip = lan_ip()
        lines += [f"{'HTTP':<12}{cfg.host}:{emu.lan_port}",
                  f"{'LAN URL':<12}http://{ip}:{emu.lan_port}",
                  f"{'Discovery':<12}UDP {cfg.host}:{emu.udp_port} (beacon {'on' if cfg.beacon else 'off'})"]
    else:
        lines.append(f"{'LAN':<12}disabled (--no-lan)")
    lines += [f"{'Device':<12}{cfg.serial} · {cfg.model} · v{VERSION}",
              f"{'Mode':<12}{cfg.mode}"]
    if cfg.mode in ("error", "reversal_decline"):
        rc = resolve_code(cfg.code)
        lines.append(f"{'Code':<12}{rc} — {code_label(rc)}")
    if cfg.mode == "decline":
        lines.append(f"{'Code':<12}100 — Do not honour")
    if cfg.mode in ("timeout", "reversal_timeout"):
        lines.append(f"{'Timeout':<12}{cfg.timeout_after:g} s")
    if cfg.delay:
        lines.append(f"{'Card delay':<12}{cfg.delay:g} s")
    lines += [f"{'Magic':<12}…00 approve · …05 decline · …08 cancel · …51 timeout",
              f"{'Admin key':<12}{emu.state.admin_key}",
              f"{'State':<12}{cfg.state_file}"]
    if cloud_base:
        lines += [f"{'Cloud':<12}{api_root(cloud_base)}", f"{'Console':<12}p = new cloud pairing code"]
    say()
    say(boxed(f"Aslan Omni Terminal Emulator v{VERSION}", lines))
    say()
    say("  Ctrl-C to stop\n")


# ── Self-check ────────────────────────────────────────────────────────────────

def run_selfcheck() -> bool:
    """Pair, sign a /pay and answer a discovery probe without any socket."""
    global QUIET
    QUIET = True
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(state_file=os.path.join(tmp, "terminal.json"), lan=False)
        emu = Emulator(cfg)
        json_h = {"Content-Type": "application/json"}
        r = emu.api.handle("POST", "/pair/request", json_h,
                           b'{"posId":"SELF","posLabel":"Self","clientNonce":"n"}', "127.0.0.1")
        sid = r.body["sessionId"]
        r = emu.api.handle("POST", "/pair/confirm", json_h,
                           json.dumps({"sessionId": sid, "pin": emu.state.last_pin}).encode(), "127.0.0.1")
        token_id, secret = r.body["tokenId"], bytes.fromhex(r.body["tokenSecret"])
        body = b'{"ref":"SELFCHECK","amountCents":1000}'
        ts = str(int(time.time()))
        sig = lan_signature(hmac_hex(secret, token_id.encode()), token_id, ts, "POST", "/pay", body)
        r = emu.api.handle("POST", "/pay", {"Authorization": f"OMNI-TOKEN tokenId={token_id},ts={ts},sig={sig}"},
                           body, "127.0.0.1")
        pay_ok = r.status == 200 and r.body["status"] == "approved"
        reply = json.loads(discovery_reply(emu.state, cfg, "abc"))
        disc_ok = reply["hmac"] == hmac_hex(emu.state.discovery_key, b"abc")
    ok = pay_ok and disc_ok
    print("selfcheck:", "OK" if ok else f"FAIL (pay={pay_ok} discovery={disc_ok})")
    return ok


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Aslan Omni terminal emulator (LAN + cloud device)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--host", default="0.0.0.0", help="Bind address for HTTP and UDP (default: 0.0.0.0)")
    p.add_argument("--lan-port", type=int, default=HTTP_PORT, help=f"HTTP port (default: {HTTP_PORT})")
    p.add_argument("--udp-port", type=int, default=UDP_PORT, help=f"UDP discovery port (default: {UDP_PORT})")
    p.add_argument("--no-lan", action="store_true", help="Disable the LAN half (cloud-only run)")
    p.add_argument("--no-beacon", action="store_true", help="Do not broadcast OMNI-BEACON every 30 s")
    p.add_argument("--serial", default=Config.serial, help="Device serial (discovery, claim)")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"Terminal model (default: {DEFAULT_MODEL})")
    p.add_argument("--terminal-id", default=Config.terminal_id, help="Acquirer terminal id on approvals")
    p.add_argument("--merchant-id", default=Config.merchant_id, help="Acquirer merchant id on approvals")
    p.add_argument("--mode", default="approve", choices=MODES, help="Outcome mode (default: approve)")
    p.add_argument("--code", default=DEFAULT_CODE,
                   help="RC for --mode error / reversal_decline — number (116) or scenario name "
                        "(insufficient_funds). Default: 909")
    p.add_argument("--delay", type=float, default=0.0, help="Simulated card time in seconds (default: 0)")
    p.add_argument("--timeout-after", type=float, default=PAYMENT_TIMEOUT_SEC,
                   help=f"Wait before a timeout outcome in timeout modes (default: {PAYMENT_TIMEOUT_SEC})")
    p.add_argument("--state-file", default=DEFAULT_STATE_FILE, help=f"Terminal state (default: {DEFAULT_STATE_FILE})")
    p.add_argument("--fresh", action="store_true", help="Start from empty state (tokens, transactions, keys)")
    p.add_argument("--relay", nargs="?", const=CLOUD_BASE, default=None, metavar="BASE",
                   help=f"Also run as a cloud device against BASE (default: {CLOUD_BASE})")
    p.add_argument("--device-token", default=os.environ.get("OMNI_DEVICE_TOKEN"),
                   help="Cloud device token (default: $OMNI_DEVICE_TOKEN)")
    p.add_argument("--token-file", default=DEFAULT_TOKEN_FILE, help=f"Device token cache (default: {DEFAULT_TOKEN_FILE})")
    p.add_argument("--save-token", action="store_true", help="Persist --device-token to the token file")
    p.add_argument("--reset", action="store_true", help="Delete the cached device token (re-onboard with --relay)")
    p.add_argument("--selfcheck", action="store_true", help="Verify pairing, signing and discovery, then exit")
    p.add_argument("--debug", action="store_true", help="Log request and response bodies")
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.selfcheck:
        sys.exit(0 if run_selfcheck() else 1)
    if args.reset:
        removed = reset_device_token(args.token_file)
        log.info(f"[reset] {'deleted ' + args.token_file if removed else 'no cached device token'}")
        if not args.relay:
            return
    if args.no_lan and not args.relay:
        p.error("--no-lan needs --relay (nothing would run)")

    cfg = Config(mode=args.mode, code=args.code, delay=args.delay, timeout_after=args.timeout_after,
                 terminal_id=args.terminal_id, merchant_id=args.merchant_id, serial=args.serial,
                 model=args.model, host=args.host, lan_port=args.lan_port, udp_port=args.udp_port,
                 lan=not args.no_lan, beacon=not args.no_beacon, state_file=args.state_file, fresh=args.fresh)
    emu = Emulator(cfg)
    try:
        emu.start()
    except OSError as e:
        log.error(f"Cannot bind {cfg.host} (HTTP {cfg.lan_port} / UDP {cfg.udp_port}) — {e}")
        sys.exit(1)
    print_banner(emu, args.relay)

    cloud = None
    if args.relay:
        token = acquire_device_token(args.relay, cfg, args.token_file, args.device_token, args.save_token)
        cloud = CloudDevice(args.relay, token, emu)
        CONSOLE_COMMANDS["p"] = cloud.initiate_pairing
        cloud.start()
    if args.mode == "interactive" or cloud:
        threading.Thread(target=_stdin_reader, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        say("\n  Stopped.")
    finally:
        if cloud:
            cloud.stop()
        emu.stop()


if __name__ == "__main__":
    main()
