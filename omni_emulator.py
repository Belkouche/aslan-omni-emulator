#!/usr/bin/env python3
"""Aslan Omni terminal + cloud-device emulator (stdlib only)."""
import argparse
import hashlib
import hmac
import json
import os
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


# ── Pairing store (LAN) ─────────────────────────────────────────────────────
TS_TOLERANCE_SEC = 30
SESSION_TTL_SEC = 300


class PairError(Exception):
    pass


class PairingStore:
    """In-memory pairing sessions + issued POS tokens for the LAN terminal."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._tokens: dict[str, dict] = {}
        self._lock = threading.Lock()

    def begin(self, pos_id: str, pos_label: str) -> tuple[str, str]:
        session_id = secrets.token_hex(16)
        pin = f"{random.randint(0, 999999):06d}"
        with self._lock:
            self._sessions[session_id] = {
                "pinHash": sha256_hex(pin.encode()),
                "posId": pos_id, "posLabel": pos_label,
                "exp": time.time() + SESSION_TTL_SEC,
            }
        return session_id, pin

    def confirm(self, session_id: str, pin: str, pos_id: str, pos_label: str) -> dict:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s or s["exp"] < time.time():
                raise PairError("invalid or expired session")
            if not hmac.compare_digest(s["pinHash"], sha256_hex(pin.encode())):
                raise PairError("wrong pin")
            del self._sessions[session_id]
            token_secret = secrets.token_bytes(32)
            token_id = secrets.token_hex(16)
            token_hmac = hmac_hex(token_secret, token_id.encode())
            self._tokens[token_id] = {
                "tokenHmac": token_hmac, "posId": pos_id, "posLabel": pos_label,
                "createdAt": datetime.now().isoformat(),
            }
        return {
            "tokenId": token_id, "tokenSecret": token_secret.hex(),
            "posId": pos_id, "terminalModel": "P3",
        }

    def verify(self, token_id: str, ts: str, method: str, path: str,
               body: bytes, sig: str) -> tuple[bool, str | None]:
        try:
            if abs(int(time.time()) - int(ts)) > TS_TOLERANCE_SEC:
                return False, "timestamp out of window"
        except ValueError:
            return False, "bad timestamp"
        tok = self._tokens.get(token_id)
        if not tok:
            return False, "unknown token"
        expected = lan_expected_sig(tok["tokenHmac"], token_id, ts, method, path, body)
        if not hmac.compare_digest(expected, sig):
            return False, "invalid signature"
        return True, None

    def list_pos(self) -> list[dict]:
        with self._lock:
            return [
                {"tokenId": tid, "posId": t["posId"], "posLabel": t["posLabel"],
                 "createdAt": t["createdAt"]}
                for tid, t in self._tokens.items()
            ]

    def revoke(self, token_id: str) -> bool:
        with self._lock:
            return self._tokens.pop(token_id, None) is not None
# ── Shared context ──────────────────────────────────────────────────────────
class EmulatorContext:
    """Shared state + config across LAN and cloud halves."""

    def __init__(self, mode: str, error_code: str, terminal_id: str = "EMU-TID",
                 merchant_id: str = "EMU-MID", serial: str = "EMU-SERIAL",
                 debug: bool = False) -> None:
        self.mode = mode
        self.error_code = error_code
        self.terminal_id = terminal_id
        self.merchant_id = merchant_id
        self.serial = serial
        self.debug = debug
        self.pairing = PairingStore()
        self.pairing.last_pin = None  # test hook: last PIN printed
        self._paid_refs: dict[str, dict] = {}   # ref -> PayResult (idempotency)
        self._lock = threading.Lock()

    def resolve_payment(self, ref: str, amount_centimes: int) -> dict:
        with self._lock:
            if ref in self._paid_refs:
                return self._paid_refs[ref]
            outcome = decide_outcome(amount_centimes, self.mode, self.error_code)
            if self.mode == "interactive":
                outcome = ask_operator(ref, amount_centimes, self.error_code)
            res = pay_result(ref, amount_centimes, outcome, self.terminal_id, self.merchant_id)
            self._paid_refs[ref] = res
            return res


# ── LAN HTTP server ─────────────────────────────────────────────────────────
def make_lan_server(host: str, port: int, ctx: EmulatorContext) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            if ctx.debug:
                super().log_message(*a)

        def _send(self, code: int, obj: dict | None):
            payload = json.dumps(obj).encode() if obj is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(n) if n else b""

        def _auth(self, body: bytes) -> tuple[str | None, str | None]:
            h = self.headers.get("Authorization", "")
            if not h.startswith("OMNI-TOKEN "):
                return None, "missing Authorization"
            parts = dict(p.split("=", 1) for p in h[len("OMNI-TOKEN "):].split(","))
            ok, err = ctx.pairing.verify(parts.get("tokenId", ""), parts.get("ts", ""),
                                         self.command, self.path, body, parts.get("sig", ""))
            return (parts["tokenId"], None) if ok else (None, err)

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"status": "ok", "version": "1.0.12", "napsPay": "installed"})
            if self.path == "/admin/pos":
                _, err = self._auth(b"")
                if err:
                    return self._send(401, {"error": err})
                return self._send(200, {"pos": ctx.pairing.list_pos()})
            self._send(404, {"error": "not found"})

        def do_DELETE(self):
            if self.path.startswith("/admin/pos/"):
                _, err = self._auth(b"")
                if err:
                    return self._send(401, {"error": err})
                token_id = self.path.rsplit("/", 1)[-1]
                ctx.pairing.revoke(token_id)
                return self._send(204, None)
            self._send(404, {"error": "not found"})

        def do_POST(self):
            body = self._read_body()
            if self.path == "/pair/request":
                req = json.loads(body or b"{}")
                sid, pin = ctx.pairing.begin(req.get("posId", ""), req.get("posLabel", ""))
                ctx.pairing.last_pin = pin
                print(f"[LAN pair] PIN for '{req.get('posLabel','')}': {pin}  (type this into your app)")
                return self._send(200, {"sessionId": sid, "expiresIn": SESSION_TTL_SEC})
            if self.path == "/pair/confirm":
                req = json.loads(body or b"{}")
                try:
                    tok = ctx.pairing.confirm(req["sessionId"], req["pin"],
                                              req.get("posId", ""), req.get("posLabel", ""))
                    return self._send(200, tok)
                except (PairError, KeyError) as ex:
                    return self._send(400, {"error": str(ex) or "invalid or expired session"})
            if self.path in ("/pay", "/reversal"):
                _, err = self._auth(body)
                if err:
                    return self._send(401, {"error": err})
                req = json.loads(body or b"{}")
                if self.path == "/reversal":
                    return self._send(200, {
                        "status": "reversed", "ref": req.get("ref"),
                        "responseCode": "000", "stan": req.get("stan"),
                    })
                res = ctx.resolve_payment(req["ref"], int(req["amountCents"]))
                return self._send(200, res)
            self._send(404, {"error": "not found"})

    return ThreadingHTTPServer((host, port), Handler)


# ── UDP discovery ───────────────────────────────────────────────────────────
def run_udp_discovery(host: str, port: int, ctx: EmulatorContext, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    reply = json.dumps({"device": ctx.serial, "model": "P3",
                        "version": "1.0.12", "hmac": "emulated"}).encode()
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue
        if data.startswith(b"OMNI-DISC:"):
            sock.sendto(reply, addr)
    sock.close()


# ── Cloud: token persistence ────────────────────────────────────────────────
DEFAULT_TOKEN_FILE = os.path.expanduser("~/.aslan-omni-emulator/device.json")


def save_device_token(path: str, rec: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)


def load_device_token(path: str, cloud_base: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    return rec if rec.get("cloudBase") == cloud_base else None


def reset_device_token(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False


# ── Cloud: HTTP with device signing ─────────────────────────────────────────
def cloud_request(base: str, method: str, path: str, device_token: str,
                  body_obj: dict | None = None, stream: bool = False):
    body = json.dumps(body_obj).encode() if body_obj is not None else b""
    headers = {"Authorization": device_auth_header(device_token, method, path, body)}
    if body:
        headers["Content-Type"] = "application/json"
    if stream:
        headers["Accept"] = "text/event-stream"
    req = urllib.request.Request(base + path, data=(body or None), method=method, headers=headers)
    return urllib.request.urlopen(req, timeout=None if stream else 30)


# ── Cloud: SSE parsing ──────────────────────────────────────────────────────
def parse_sse(lines):
    """Yield (event, data_obj) tuples from an iterator of decoded SSE lines."""
    event, data = None, None
    for line in lines:
        if line == "":
            if event is not None and data is not None:
                try:
                    yield event, json.loads(data)
                except json.JSONDecodeError:
                    pass
            event, data = None, None
        elif line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data = line[len("data:"):].strip()


# ── Cloud: result payloads ──────────────────────────────────────────────────
def result_payload_for_pay(outcome: dict) -> dict:
    return {
        "status": outcome["status"],
        "responseCode": outcome.get("responseCode"),
        "authNumber": outcome.get("authNumber"),
        "stan": outcome.get("stan"),
        "rrn": outcome.get("rrn"),
        "cardNumber": outcome.get("cardNumber"),
        "cardScheme": outcome.get("cardScheme"),
        "txDate": outcome.get("transactionDate"),
        "txTime": outcome.get("transactionTime"),
    }


def result_payload_for_reverse(stan: str) -> dict:
    return {"status": "reversed", "responseCode": "000", "stan": stan}


# ── Cloud: claim + relay loop ───────────────────────────────────────────────
def acquire_device_token(base: str, token_file: str, explicit: str | None,
                         save: bool, serial: str) -> dict:
    if explicit:
        rec = {"deviceToken": explicit, "deviceId": None, "merchantId": None,
               "merchantName": None, "cloudBase": base}
        if save:
            save_device_token(token_file, rec)
        return rec
    cached = load_device_token(token_file, base)
    if cached:
        print(f"[Cloud] using cached device token from {token_file}")
        return cached
    print("[Cloud] no device token — starting claim…")
    resp = _cloud_json(base, "POST", "/devices/claim",
                       {"serial": serial, "model": "P3", "appVersion": "emulator"})
    uuid, claim_url = resp["uuid"], resp["claimUrl"]
    print(f"[Cloud] Activate this device: {claim_url}\n[Cloud] waiting for activation…")
    while True:
        time.sleep(3)
        status = _cloud_json(base, "GET", f"/devices/claim/{uuid}/status", None)
        if status.get("status") == "activated" and status.get("deviceToken"):
            rec = {"deviceToken": status["deviceToken"], "deviceId": None,
                   "merchantId": status.get("merchantId"),
                   "merchantName": status.get("merchantName"), "cloudBase": base}
            save_device_token(token_file, rec)
            print("[Cloud] activated — token cached.")
            return rec


def _cloud_json(base: str, method: str, path: str, body_obj: dict | None) -> dict:
    """Unauthenticated cloud call (claim/status are not device-authed)."""
    body = json.dumps(body_obj).encode() if body_obj is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def run_cloud_relay(base: str, ctx: EmulatorContext, device_token: str,
                    stop: threading.Event) -> None:
    backoff = 3
    while not stop.is_set():
        try:
            code = cloud_request(base, "POST", "/cloud/pair/initiate", device_token, {})
            code_obj = json.loads(code.read())
            print(f"[Cloud] pairing code: {code_obj.get('pairingCode')}  (enter via pairCloud)")
            resp = cloud_request(base, "GET", "/cloud/stream", device_token, stream=True)
            print("[Cloud] SSE connected.")
            backoff = 3
            lines = (raw.decode("utf-8", "replace").rstrip("\n") for raw in resp)
            for event, data in parse_sse(lines):
                if stop.is_set():
                    break
                _handle_cloud_event(base, ctx, device_token, event, data)
        except Exception as ex:  # noqa: BLE001
            print(f"[Cloud] disconnected: {ex}; retrying in {backoff}s")
            if stop.wait(backoff):
                break
            backoff = min(backoff * 2, 60)


def _handle_cloud_event(base: str, ctx: EmulatorContext, device_token: str,
                        event: str, data: dict) -> None:
    if event == "PayCommand":
        amount = int(data["amountCents"])
        outcome = decide_outcome(amount, ctx.mode, ctx.error_code)
        if ctx.mode == "interactive":
            outcome = ask_operator(data.get("ref", ""), amount, ctx.error_code)
        if outcome["status"] == "timeout":
            print(f"[Cloud] PayCommand {data['commandId']} → timeout (not posting; long-poll expires)")
            return
        cloud_request(base, "POST", f"/cloud/pay/{data['commandId']}/result",
                      device_token, result_payload_for_pay(outcome)).read()
        print(f"[Cloud] PayCommand {data['commandId']} → {outcome['status']}")
    elif event == "ReverseCommand":
        cloud_request(base, "POST", f"/cloud/pay/{data['commandId']}/result",
                      device_token, result_payload_for_reverse(data.get("stan", ""))).read()
        print(f"[Cloud] ReverseCommand {data['commandId']} → reversed")
    elif event == "Ping":
        try:
            cloud_request(base, "POST", "/cloud/ping", device_token, {}).read()
        except Exception:  # noqa: BLE001
            pass
    elif event == "PairingRevoked":
        print("[Cloud] pairing revoked by server")


# ── Interactive operator prompt ─────────────────────────────────────────────
_stdin_q: "queue.Queue[str]" = queue.Queue()
_stdin_started = False


def _start_stdin_reader() -> None:
    global _stdin_started
    if _stdin_started:
        return
    _stdin_started = True

    def _reader():
        while True:
            try:
                _stdin_q.put(input().strip().lower())
            except EOFError:
                _stdin_q.put("a")
                return
    threading.Thread(target=_reader, daemon=True).start()


_ask_lock = threading.Lock()


def ask_operator(ref: str, amount_centimes: int, error_code: str) -> dict:
    """Prompt to approve or pick a decline scenario. Auto-approve after 120s."""
    _start_stdin_reader()
    scenarios = list(SCENARIOS.items())
    with _ask_lock:
        print(f"\n  ┌── Payment  ref={ref}  {amount_centimes/100:.2f} MAD ──")
        print("  │  [a] Approve")
        for i, (name, code) in enumerate(scenarios, 1):
            print(f"  │  [{i:2d}] Decline — {name} ({code})")
        print("  └── Choice → ", end="", flush=True)
        try:
            choice = _stdin_q.get(timeout=120)
        except queue.Empty:
            print("(timeout → approve)")
            return decide_outcome(amount_centimes, "approve", error_code)
    if choice in ("", "a"):
        return decide_outcome(amount_centimes, "approve", error_code)
    if choice.isdigit() and 1 <= int(choice) <= len(scenarios):
        return {"status": "declined", "responseCode": scenarios[int(choice) - 1][1]}
    return {"status": "declined", "responseCode": resolve_code(choice)}


# ── Self-check ──────────────────────────────────────────────────────────────
def run_selfcheck() -> bool:
    store = PairingStore()
    sid, pin = store.begin("SELF", "Self")
    tok = store.confirm(sid, pin, "SELF", "Self")
    token_id, secret_hex = tok["tokenId"], tok["tokenSecret"]
    derived = hmac_hex(bytes.fromhex(secret_hex), token_id.encode())
    ts = str(int(time.time()))
    body = b'{"ref":"SC","amountCents":1000}'
    sig = hmac_hex(bytes.fromhex(derived), f"{token_id}:{ts}:POST:/pay:{sha256_hex(body)}".encode())
    ok, err = store.verify(token_id, ts, "POST", "/pay", body, sig)
    print("selfcheck:", "OK" if ok else f"FAIL ({err})")
    return ok


# ── main ────────────────────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="Aslan Omni terminal + cloud-device emulator")
    p.add_argument("--lan-port", type=int, default=8080)
    p.add_argument("--udp-port", type=int, default=8481)
    p.add_argument("--no-lan", action="store_true")
    p.add_argument("--serial", default=f"EMU-{socket.gethostname()}")
    p.add_argument("--relay", nargs="?", const="https://staging-api.aslanpay.ma", default=None,
                   help="Enable cloud half against BASE (default staging).")
    p.add_argument("--device-token", default=os.environ.get("OMNI_DEVICE_TOKEN"))
    p.add_argument("--token-file", default=DEFAULT_TOKEN_FILE)
    p.add_argument("--save-token", action="store_true")
    p.add_argument("--reset", action="store_true")
    p.add_argument("--mode", default="approve",
                   choices=["approve", "decline", "error", "interactive", "timeout"])
    p.add_argument("--code", default="909")
    p.add_argument("--selfcheck", action="store_true")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    if args.selfcheck:
        sys.exit(0 if run_selfcheck() else 1)

    if args.reset:
        removed = reset_device_token(args.token_file)
        print(f"[reset] {'deleted ' + args.token_file if removed else 'no cached token'}")
        if not args.relay:
            return

    ctx = EmulatorContext(args.mode, args.code, serial=args.serial, debug=args.debug)
    stop = threading.Event()
    threads: list[threading.Thread] = []

    if not args.no_lan:
        httpd = make_lan_server("127.0.0.1", args.lan_port, ctx)
        threads.append(threading.Thread(target=httpd.serve_forever, daemon=True))
        threads.append(threading.Thread(target=run_udp_discovery,
                                        args=("", args.udp_port, ctx, stop), daemon=True))
        print(f"LAN terminal: http://127.0.0.1:{args.lan_port}  (discovery UDP :{args.udp_port})")

    if args.relay:
        rec = acquire_device_token(args.relay, args.token_file, args.device_token,
                                   args.save_token, args.serial)
        threads.append(threading.Thread(
            target=run_cloud_relay, args=(args.relay, ctx, rec["deviceToken"], stop), daemon=True))
        print(f"Cloud relay: {args.relay}")

    for t in threads:
        t.start()
    print(f"Emulator ready (mode={args.mode}). Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        print("\nBye.")


if __name__ == "__main__":
    main()
