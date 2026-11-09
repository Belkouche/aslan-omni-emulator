"""
Tests for omni_emulator.py — stdlib unittest (pytest runs them too).

Real servers on ephemeral ports, temp state files, tiny delays. The cloud half
runs against FakeCloud, an in-process stand-in for aslan-omni-api that verifies
the device OMNI-TOKEN signature and the /omni prefix.

    python3 -m unittest -v test_omni_emulator
    python3 -m pytest -q
"""

import base64
import contextlib
import hashlib
import hmac
import http.client
import io
import json
import logging
import os
import queue
import random
import re
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import omni_emulator as omni

omni.QUIET = True
logging.getLogger("omni-emulator").setLevel(logging.CRITICAL)

JSON = {"Content-Type": "application/json"}


def wait_until(pred, timeout: float = 5.0, interval: float = 0.02) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return pred()


# ── Test-side RSA (key generation, SPKI encoding, OAEP decryption) ────────────

def _probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(20):
        x = pow(random.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _probable_prime(c):
            return c


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


def _der_int(x: int) -> bytes:
    raw = x.to_bytes((x.bit_length() + 8) // 8, "big")   # leading 0x00 keeps it positive
    return _der(0x02, raw)


def make_rsa_key(bits: int = 1024) -> tuple[str, int, int]:
    """Return (spki_b64, n, d)."""
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            break
    n, d = p * q, pow(e, -1, (p - 1) * (q - 1))
    alg = _der(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")
    spki = _der(0x30, alg + _der(0x03, b"\x00" + _der(0x30, _der_int(n) + _der_int(e))))
    return base64.b64encode(spki).decode(), n, d


def oaep_decrypt(c_b64: str, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(base64.b64decode(c_b64), "big"), d, n).to_bytes(k, "big")
    assert em[0] == 0
    masked_seed, masked_db = em[1:33], em[33:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, omni._mgf1_sha256(masked_db, 32)))
    db = bytes(a ^ b for a, b in zip(masked_db, omni._mgf1_sha256(seed, k - 33)))
    assert db[:32] == hashlib.sha256(b"").digest()
    return db[db.index(b"\x01", 32) + 1:]


# ── LAN harness ───────────────────────────────────────────────────────────────

class EmuTestCase(unittest.TestCase):
    """Starts one emulator per test (HTTP + UDP on ephemeral ports, temp state)."""

    config: dict = {}
    strict_limits = False

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmpdir = tmp.name
        self.state_file = os.path.join(self.tmpdir, "terminal.json")
        while not omni._stdin_queue.empty():
            omni._stdin_queue.get_nowait()
        self.emu = self.make_emu(**self.config)

    def make_emu(self, **kw) -> omni.Emulator:
        kw.setdefault("state_file", self.state_file)
        cfg = omni.Config(host="127.0.0.1", lan_port=0, udp_port=0, beacon=False, **kw)
        emu = omni.Emulator(cfg)
        if not self.strict_limits:
            emu.state.limiter.max = emu.state.limiter.global_max = 10_000
        emu.start()
        self.addCleanup(emu.stop)
        return emu

    def call(self, method: str, path: str, body=None, headers=None, emu=None):
        """Return (status, parsed JSON or None, raw bytes)."""
        emu = emu or self.emu
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        conn = http.client.HTTPConnection("127.0.0.1", emu.lan_port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            raw = r.read()
        finally:
            conn.close()
        return r.status, (json.loads(raw) if raw else None), raw

    def pair(self, pos_id="POS-1", label="Till 1", pub_key=None, emu=None) -> tuple[str, bytes]:
        emu = emu or self.emu
        req = {"posId": pos_id, "posLabel": label, "clientNonce": "nonce-1"}
        if pub_key:
            req["clientPubKey"] = pub_key
        status, obj, _ = self.call("POST", "/pair/request", req, JSON, emu)
        self.assertEqual(status, 200, obj)
        status, tok, _ = self.call("POST", "/pair/confirm",
                                   {"sessionId": obj["sessionId"], "pin": emu.state.last_pin}, JSON, emu)
        self.assertEqual(status, 200, tok)
        return tok["tokenId"], bytes.fromhex(tok["tokenSecret"]) if "tokenSecret" in tok else b""

    @staticmethod
    def auth_header(token, method, path, body: bytes, ts=None) -> str:
        token_id, secret = token
        ts = str(int(time.time())) if ts is None else str(ts)
        sig = omni.lan_signature(omni.hmac_hex(secret, token_id.encode()), token_id, ts, method, path, body)
        return f"OMNI-TOKEN tokenId={token_id},ts={ts},sig={sig}"

    def signed(self, method, path, body_obj, token, sign_path=None, emu=None):
        body = json.dumps(body_obj).encode() if body_obj is not None else b""
        sign_path = sign_path or path.split("?")[0]
        headers = {"Authorization": self.auth_header(token, method, sign_path, body)}
        if body:
            headers["Content-Type"] = "application/json"
        return self.call(method, path, body or None, headers, emu)

    def pay(self, ref, amount, token, emu=None):
        return self.signed("POST", "/pay", {"ref": ref, "amountCents": amount}, token, emu=emu)


# ── Health, routing, Gson shape ───────────────────────────────────────────────

class HealthAndRoutingTests(EmuTestCase):

    def test_health_exact_body(self):
        status, _, raw = self.call("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(raw, b'{"status":"ok","version":"1.3.5","napsPay":"installed"}')

    def test_unknown_routes_are_404_with_empty_body(self):
        token = self.pair()
        for method, path in [("POST", "/reverse"), ("GET", "/pay"), ("POST", "/pay/"), ("GET", "/nope")]:
            status, _, raw = self.signed(method, path, {"ref": "x"} if method == "POST" else None, token)
            self.assertEqual((status, raw), (404, b""), f"{method} {path}")

    def test_selfcheck_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(omni.run_selfcheck())
        omni.QUIET = True
        self.assertIn("selfcheck: OK", out.getvalue())


# ── Pairing ───────────────────────────────────────────────────────────────────

class PairingTests(EmuTestCase):

    def test_cleartext_pairing_uses_session_identity(self):
        status, obj, _ = self.call("POST", "/pair/request",
                                   {"posId": "POS-A", "posLabel": "Front", "clientNonce": "n"}, JSON)
        self.assertEqual(status, 200)
        self.assertEqual(obj["expiresIn"], 120)
        self.assertRegex(obj["sessionId"], r"^[0-9a-f-]{36}$")
        self.assertRegex(self.emu.state.last_pin, r"^\d{6}$")
        status, tok, _ = self.call("POST", "/pair/confirm",
                                   {"sessionId": obj["sessionId"], "pin": self.emu.state.last_pin,
                                    "posId": "EVIL"}, JSON)
        self.assertEqual(status, 200)
        self.assertEqual(set(tok), {"tokenId", "posId", "terminalModel", "tokenSecret"})
        self.assertEqual(tok["posId"], "POS-A")
        self.assertEqual(tok["terminalModel"], "P3")
        self.assertRegex(tok["tokenSecret"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.emu.state.tokens[tok["tokenId"]]["posLabel"], "Front")
        status, _, _ = self.pay("R1", 1000, (tok["tokenId"], bytes.fromhex(tok["tokenSecret"])))
        self.assertEqual(status, 200)

    def test_encrypted_pairing_secret_decrypts_and_signs(self):
        spki, n, d = make_rsa_key()
        status, obj, _ = self.call("POST", "/pair/request",
                                   {"posId": "POS-E", "posLabel": "Enc", "clientNonce": "n", "clientPubKey": spki}, JSON)
        status, tok, raw = self.call("POST", "/pair/confirm",
                                     {"sessionId": obj["sessionId"], "pin": self.emu.state.last_pin}, JSON)
        self.assertEqual(status, 200, tok)
        self.assertNotIn("tokenSecret", tok)
        self.assertIn(b"\\u003d", raw)      # Gson escapes base64 '=' padding
        secret = oaep_decrypt(tok["encryptedTokenSecret"], n, d)
        self.assertEqual(len(secret), 32)
        status, res, _ = self.pay("ENC-1", 1000, (tok["tokenId"], secret))
        self.assertEqual((status, res["status"]), (200, "approved"))

    def test_bad_client_pub_key_refused_at_confirm(self):
        _, obj, _ = self.call("POST", "/pair/request",
                              {"posId": "P", "posLabel": "L", "clientNonce": "n", "clientPubKey": "bm90IGEga2V5"}, JSON)
        status, body, _ = self.call("POST", "/pair/confirm",
                                    {"sessionId": obj["sessionId"], "pin": self.emu.state.last_pin}, JSON)
        self.assertEqual((status, body), (400, {"error": "invalid clientPubKey"}))

    def test_wrong_pin_lockout_after_five(self):
        _, obj, _ = self.call("POST", "/pair/request", {"posId": "P", "posLabel": "L", "clientNonce": "n"}, JSON)
        pin = self.emu.state.last_pin
        wrong = f"{(int(pin) + 1) % 1_000_000:06d}"
        for _ in range(5):
            status, body, _ = self.call("POST", "/pair/confirm", {"sessionId": obj["sessionId"], "pin": wrong}, JSON)
            self.assertEqual((status, body), (400, {"error": "wrong pin"}))
        for _ in range(2):   # locked: even the right PIN is refused
            status, body, _ = self.call("POST", "/pair/confirm", {"sessionId": obj["sessionId"], "pin": pin}, JSON)
            self.assertEqual((status, body), (400, {"error": "invalid or expired session"}))

    def test_used_unknown_and_expired_sessions(self):
        _, obj, _ = self.call("POST", "/pair/request", {"posId": "P", "posLabel": "L", "clientNonce": "n"}, JSON)
        pin = self.emu.state.last_pin
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": obj["sessionId"], "pin": pin}, JSON)[0], 200)
        expired = (400, {"error": "invalid or expired session"})
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": obj["sessionId"], "pin": pin}, JSON)[:2], expired)
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": "nope", "pin": pin}, JSON)[:2], expired)
        _, obj, _ = self.call("POST", "/pair/request", {"posId": "P", "posLabel": "L", "clientNonce": "n"}, JSON)
        self.emu.state.sessions[obj["sessionId"]]["expiresAt"] = int(time.time()) - 1   # TTL elapsed
        self.assertEqual(self.call("POST", "/pair/confirm",
                                   {"sessionId": obj["sessionId"], "pin": self.emu.state.last_pin}, JSON)[:2], expired)

    def test_malformed_pairing_bodies_are_500(self):
        internal = (500, {"error": "internal error"})
        self.assertEqual(self.call("POST", "/pair/request", {"posId": "P", "posLabel": "L"}, JSON)[:2], internal)
        self.assertEqual(self.call("POST", "/pair/request", b"{not json", JSON)[:2], internal)
        # ContentNegotiation needs a JSON content type for call.receive<Dto>()
        self.assertEqual(self.call("POST", "/pair/request",
                                   {"posId": "P", "posLabel": "L", "clientNonce": "n"})[:2], internal)
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": "x"}, JSON)[:2], internal)


class RateLimitTests(EmuTestCase):
    strict_limits = True

    def test_per_ip_limit_shared_by_request_and_confirm(self):
        body = {"posId": "P", "posLabel": "L", "clientNonce": "n"}
        for _ in range(4):
            self.assertEqual(self.call("POST", "/pair/request", body, JSON)[0], 200)
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": "x", "pin": "000000"}, JSON)[0], 400)
        self.assertEqual(self.call("POST", "/pair/request", body, JSON)[:2], (429, {"error": "rate limit exceeded"}))
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": "x", "pin": "0"}, JSON)[:2],
                         (429, {"error": "rate limit exceeded"}))

    def test_global_confirm_cap(self):
        self.emu.state.limiter.max = 10_000      # take the per-IP bucket out of the way
        for _ in range(15):
            self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": "x", "pin": "0"}, JSON)[0], 400)
        self.assertEqual(self.call("POST", "/pair/confirm", {"sessionId": "x", "pin": "0"}, JSON)[0], 429)
        self.assertEqual(self.call("POST", "/pair/request",
                                   {"posId": "P", "posLabel": "L", "clientNonce": "n"}, JSON)[0], 200)


# ── OMNI-TOKEN auth ───────────────────────────────────────────────────────────

class AuthTests(EmuTestCase):

    def setUp(self):
        super().setUp()
        self.token = self.pair()
        self.body = b'{"ref":"A1","amountCents":1000}'

    def post(self, auth):
        headers = {"Content-Type": "application/json"}
        if auth is not None:
            headers["Authorization"] = auth
        return self.call("POST", "/pay", self.body, headers)[:2]

    def assert401(self, auth, message):
        self.assertEqual(self.post(auth), (401, {"error": message}), auth)

    def test_every_401_string_in_order(self):
        tid = self.token[0]
        now = int(time.time())
        good = self.auth_header(self.token, "POST", "/pay", self.body)
        sig = good.rsplit("sig=", 1)[1]
        self.assert401(None, "missing or invalid Authorization")
        self.assert401("Bearer abc", "missing or invalid Authorization")
        self.assert401(f"OMNI-TOKEN ts={now},sig={sig}", "missing tokenId")
        self.assert401(f"OMNI-TOKEN tokenId={tid},sig={sig}", "missing ts")
        self.assert401(f"OMNI-TOKEN tokenId={tid},ts=abc,sig={sig}", "missing ts")
        self.assert401(f"OMNI-TOKEN tokenId={tid},ts={now}", "missing sig")
        self.assert401(f"OMNI-TOKEN tokenId=unknown,ts={now - 301},sig={sig}", "timestamp out of window")
        self.assert401(f"OMNI-TOKEN tokenId=unknown,ts={now},sig={sig}", "unknown token")
        self.assert401(f"OMNI-TOKEN tokenId={tid},ts={now},sig={'0' * 64}", "invalid signature")
        self.assert401(good.replace(sig, sig.upper()), "invalid signature")

    def test_parts_any_order_trimmed_and_drift_tolerated(self):
        ts = int(time.time()) - 250
        hdr = self.auth_header(self.token, "POST", "/pay", self.body, ts=ts)
        parts = hdr[len("OMNI-TOKEN "):].split(",")
        status, res = self.post("OMNI-TOKEN " + " , ".join(reversed(parts)) + ",junk")
        self.assertEqual((status, res["status"]), (200, "approved"))

    def test_signature_covers_path_without_query(self):
        status, res, _ = self.signed("POST", "/pay?debug=1", {"ref": "Q1", "amountCents": 1000}, self.token,
                                     sign_path="/pay")
        self.assertEqual((status, res["status"]), (200, "approved"))
        status, res, _ = self.signed("POST", "/pay?debug=1", {"ref": "Q2", "amountCents": 1000}, self.token,
                                     sign_path="/pay?debug=1")
        self.assertEqual((status, res), (401, {"error": "invalid signature"}))

    def test_body_is_part_of_signature(self):
        hdr = self.auth_header(self.token, "POST", "/pay", b'{"ref":"other","amountCents":1000}')
        self.assert401(hdr, "invalid signature")

    def test_malformed_pay_body_with_valid_auth_is_500(self):
        for body in (b"{oops", b'{"ref":"X"}', b'{"amountCents":1000}', b'{"ref":"X","amountCents":"abc"}'):
            hdr = self.auth_header(self.token, "POST", "/pay", body)
            status, res, _ = self.call("POST", "/pay", body, {"Authorization": hdr})
            self.assertEqual((status, res), (500, {"error": "internal error"}), body)


# ── /pay results and idempotency ──────────────────────────────────────────────

class PayTests(EmuTestCase):

    def setUp(self):
        super().setUp()
        self.token = self.pair()

    def test_approved_shape(self):
        status, res, raw = self.signed("POST", "/pay", {"ref": "S1", "amountCents": 12345, "cashierId": "c1",
                                                        "tillId": "t1", "description": "x", "printReceipt": True},
                                       self.token)
        self.assertEqual(status, 200)
        self.assertEqual(set(res), {"status", "ref", "responseCode", "authNumber", "stan", "cardNumber",
                                    "cardScheme", "terminalId", "merchantId", "transactionDate",
                                    "transactionTime", "amountCents"})
        self.assertEqual((res["status"], res["responseCode"], res["ref"], res["amountCents"]),
                         ("approved", "000", "S1", 12345))
        self.assertRegex(res["authNumber"], r"^\d{6}$")
        self.assertRegex(res["stan"], r"^\d{6}$")
        self.assertEqual((res["cardNumber"], res["cardScheme"]), ("516794******3315", "MASTERCARD"))
        self.assertRegex(res["transactionDate"], r"^\d{2}/\d{2}/\d{4}$")
        self.assertRegex(res["transactionTime"], r"^\d{2}:\d{2}:\d{2}$")
        self.assertNotIn(b"rrn", raw)
        self.assertNotIn(b" ", raw)              # compact JSON

    def test_no_amount_validation(self):
        status, res, _ = self.pay("ZERO", 0, self.token)
        self.assertEqual((status, res["status"]), (200, "approved"))

    def test_idempotency_matrix(self):
        _, first, _ = self.pay("OK-1", 1000, self.token)
        _, again, _ = self.pay("OK-1", 9999, self.token)     # cached; amount not compared
        self.assertEqual(again, first)
        for ref, amount, status in [("DEC-1", 1005, "declined"), ("CAN-1", 1008, "cancelled"), ("TMO-1", 1051, "timeout")]:
            _, res, _ = self.pay(ref, amount, self.token)
            self.assertEqual(res["status"], status)
            _, res, _ = self.pay(ref, 2000, self.token)       # no money moved → charged again
            self.assertEqual((res["status"], res["amountCents"]), ("approved", 2000), ref)
        self.emu.state.transactions["OK-1"]["status"] = "reversed"
        _, res, _ = self.pay("OK-1", 1000, self.token)
        self.assertEqual((res["status"], res["stan"]), ("reversed", first["stan"]))
        self.emu.state.transactions["OK-1"]["status"] = "pending"
        self.assertEqual(self.pay("OK-1", 1000, self.token)[:2], (409, {"error": "ref already in progress"}))

    def test_concurrent_same_ref_gets_409(self):
        self.emu.cfg.delay = 0.4
        results = []

        def go():
            results.append(self.pay("RACE", 1000, self.token)[:2])

        threads = [threading.Thread(target=go) for _ in range(2)]
        threads[0].start()
        time.sleep(0.1)
        threads[1].start()
        for t in threads:
            t.join()
        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [200, 409])
        self.assertIn((409, {"error": "ref already in progress"}), results)


# ── Reversal and admin routes ─────────────────────────────────────────────────

class ReversalTests(EmuTestCase):

    def setUp(self):
        super().setUp()
        self.token_a = self.pair("POS-A")
        self.token_b = self.pair("POS-B")
        _, self.sale, _ = self.pay("SALE-1", 5000, self.token_a)

    def reverse(self, token, original_ref="SALE-1", stan=None):
        return self.signed("POST", "/reversal", {"ref": "REV-1", "originalRef": original_ref,
                                                 "stan": stan or self.sale["stan"]}, token)[:2]

    def test_owner_reverses_and_original_is_unchanged(self):
        self.assertEqual(self.reverse(self.token_a), (200, {"status": "reversed", "ref": "REV-1", "responseCode": "000"}))
        self.assertEqual(self.emu.state.transactions["SALE-1"]["status"], "approved")

    def test_forbidden_cases(self):
        forbidden = (403, {"error": "not authorized to reverse this transaction"})
        self.assertEqual(self.reverse(self.token_b), forbidden)
        self.assertEqual(self.reverse(self.token_a, stan="000000"), forbidden)
        self.assertEqual(self.reverse(self.token_a, original_ref="NOPE"), forbidden)

    def test_admin_reversal(self):
        key = {"X-Admin-Key": self.emu.state.admin_key, **JSON}
        body = {"originalRef": "SALE-1", "reversalRef": "AREV-1"}
        self.assertEqual(self.call("POST", "/admin/reversal", body, {"X-Admin-Key": "wrong"})[:2],
                         (401, {"error": "invalid admin key"}))
        self.assertEqual(self.call("POST", "/admin/reversal", body)[:2], (401, {"error": "invalid admin key"}))
        self.assertEqual(self.call("POST", "/admin/reversal", {"originalRef": "NOPE", "reversalRef": "x"}, key)[:2],
                         (404, {"error": "transaction not found"}))
        self.assertEqual(self.call("POST", "/admin/reversal", body, key)[:2],
                         (200, {"status": "reversed", "ref": "AREV-1", "responseCode": "000"}))
        self.pay("DECL-1", 1005, self.token_a)
        self.assertEqual(self.call("POST", "/admin/reversal", {"originalRef": "DECL-1", "reversalRef": "x"}, key)[:2],
                         (422, {"error": "no STAN on record — cannot reverse"}))
        self.emu.state.transactions["STUCK"] = {"ref": "STUCK", "status": "pending", "amountCents": 1,
                                                "createdAt": int(time.time() * 1000)}
        self.assertEqual(self.call("POST", "/admin/reversal", {"originalRef": "STUCK", "reversalRef": "x"}, key)[:2],
                         (200, {"status": "cancelled", "ref": "STUCK", "note": "pending cleared locally"}))
        self.assertEqual(self.emu.state.transactions["STUCK"]["status"], "cancelled")
        self.assertEqual(self.pay("STUCK", 1000, self.token_a)[1]["status"], "approved")

    def test_admin_pos_list_and_revoke(self):
        status, obj, _ = self.signed("GET", "/admin/pos", None, self.token_a)
        self.assertEqual(status, 200)
        self.assertEqual(len(obj["pos"]), 1)
        entry = obj["pos"][0]
        self.assertEqual(set(entry), {"tokenId", "posId", "posLabel", "createdAt"})
        self.assertEqual((entry["tokenId"], entry["posId"]), (self.token_a[0], "POS-A"))
        self.assertIsInstance(entry["createdAt"], int)
        self.assertLess(abs(entry["createdAt"] - time.time()), 60)
        self.assertEqual(self.signed("DELETE", f"/admin/pos/{self.token_b[0]}", None, self.token_a)[:2],
                         (403, {"error": "forbidden"}))
        status, obj, raw = self.signed("DELETE", f"/admin/pos/{self.token_a[0]}", None, self.token_a)
        self.assertEqual((status, raw), (204, b""))
        self.assertEqual(self.signed("GET", "/admin/pos", None, self.token_a)[:2], (401, {"error": "unknown token"}))
        self.assertEqual(self.signed("GET", "/admin/pos", None, self.token_b)[0], 200)


# ── Modes, magic amounts, delay ───────────────────────────────────────────────

class ModeTests(EmuTestCase):

    def run_mode(self, **cfg):
        emu = self.make_emu(state_file=os.path.join(self.tmpdir, f"{random.random()}.json"), **cfg)
        return emu, self.pair(emu=emu)

    def test_decline_error_cancel(self):
        emu, tok = self.run_mode(mode="decline")
        self.assertEqual(self.pay("D", 1234, tok, emu)[1], {"status": "declined", "ref": "D", "responseCode": "100",
                                                            "amountCents": 1234})
        emu, tok = self.run_mode(mode="error", code="insufficient_funds")
        self.assertEqual(self.pay("E1", 1234, tok, emu)[1]["responseCode"], "116")
        emu, tok = self.run_mode(mode="error", code="117")
        self.assertEqual(self.pay("E2", 1234, tok, emu)[1]["responseCode"], "117")
        emu, tok = self.run_mode(mode="cancel")
        self.assertEqual(self.pay("C", 1234, tok, emu)[1], {"status": "cancelled", "ref": "C", "responseCode": "099",
                                                            "amountCents": 1234})

    def test_timeout_mode_waits_then_has_no_card_fields(self):
        emu, tok = self.run_mode(mode="timeout", timeout_after=0.3)
        t0 = time.time()
        res = self.pay("T", 1234, tok, emu)[1]
        self.assertGreaterEqual(time.time() - t0, 0.3)
        self.assertEqual(res, {"status": "timeout", "ref": "T", "amountCents": 1234})

    def test_reversal_modes(self):
        emu, tok = self.run_mode(mode="reversal_decline")
        sale = self.pay("S", 1234, tok, emu)[1]
        self.assertEqual(sale["status"], "approved")
        rev = self.signed("POST", "/reversal", {"ref": "R", "originalRef": "S", "stan": sale["stan"]}, tok, emu=emu)[1]
        self.assertEqual(rev, {"status": "declined", "ref": "R", "responseCode": "909"})
        emu, tok = self.run_mode(mode="reversal_decline", code="wrong_pin")
        sale = self.pay("S", 1234, tok, emu)[1]
        rev = self.signed("POST", "/reversal", {"ref": "R", "originalRef": "S", "stan": sale["stan"]}, tok, emu=emu)[1]
        self.assertEqual(rev["responseCode"], "117")
        emu, tok = self.run_mode(mode="reversal_timeout", timeout_after=0.1)
        sale = self.pay("S", 1234, tok, emu)[1]
        rev = self.signed("POST", "/reversal", {"ref": "R", "originalRef": "S", "stan": sale["stan"]}, tok, emu=emu)[1]
        self.assertEqual(rev, {"status": "declined", "ref": "R"})

    def test_interactive_choices(self):
        emu, tok = self.run_mode(mode="interactive", interactive_timeout=5)
        for i, (answer, status, rc) in enumerate([("a", "approved", "000"), ("2", "declined", "117"),
                                                  ("insufficient_funds", "declined", "116"),
                                                  ("c", "cancelled", "099"), ("t", "timeout", None)]):
            omni._stdin_queue.put(answer)
            res = self.pay(f"I{i}", 1234, tok, emu)[1]
            self.assertEqual((res["status"], res.get("responseCode")), (status, rc), answer)

    def test_interactive_auto_approves(self):
        emu, tok = self.run_mode(mode="interactive", interactive_timeout=0.2)
        self.assertEqual(self.pay("AUTO", 1234, tok, emu)[1]["status"], "approved")

    def test_magic_amounts_override_mode(self):
        emu, tok = self.run_mode(mode="decline", timeout_after=30)
        cases = [(1000, "approved", "000"), (1005, "declined", "005"), (1008, "cancelled", "099"),
                 (1051, "timeout", None), (1234, "declined", "100")]
        for amount, status, rc in cases:
            t0 = time.time()
            res = self.pay(f"M{amount}", amount, tok, emu)[1]
            self.assertEqual((res["status"], res.get("responseCode")), (status, rc), amount)
            self.assertLess(time.time() - t0, 5)    # magic timeout answers at once

    def test_delay(self):
        emu, tok = self.run_mode(delay=0.3)
        t0 = time.time()
        self.assertEqual(self.pay("DLY", 1234, tok, emu)[1]["status"], "approved")
        self.assertGreaterEqual(time.time() - t0, 0.3)


# ── Discovery and persistence ─────────────────────────────────────────────────

class DiscoveryTests(EmuTestCase):

    def test_probe_reply(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(b"OMNI-DISC: nonce-123 \n", ("127.0.0.1", self.emu.udp_port))
            data, _ = s.recvfrom(1024)
            s.sendto(b"HELLO", ("127.0.0.1", self.emu.udp_port))   # ignored
            s.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                s.recvfrom(1024)
        reply = json.loads(data)
        self.assertEqual(list(reply), ["device", "model", "version", "hmac"])
        self.assertEqual((reply["device"], reply["model"], reply["version"]),
                         (self.emu.cfg.serial, "P3", "1.3.5"))
        self.assertEqual(reply["hmac"], hmac.new(self.emu.state.discovery_key, b"nonce-123", hashlib.sha256).hexdigest())


class PersistenceTests(EmuTestCase):

    def test_state_survives_restart(self):
        token = self.pair()
        sale = self.pay("P1", 1000, token)[1]
        admin_key, disc_key = self.emu.state.admin_key, self.emu.state.discovery_key
        self.emu.stop()
        emu2 = self.make_emu()
        self.assertEqual((emu2.state.admin_key, emu2.state.discovery_key), (admin_key, disc_key))
        self.assertEqual(self.pay("P1", 1000, token, emu2)[1], sale)
        self.assertEqual(self.signed("GET", "/admin/pos", None, token, emu=emu2)[0], 200)

    def test_stale_pending_becomes_timeout_and_fresh_ignores_state(self):
        token = self.pair()
        old_ms = int((time.time() - 300) * 1000)
        self.emu.state.transactions["STALE"] = {"ref": "STALE", "status": "pending", "amountCents": 1, "createdAt": old_ms}
        self.emu.state.transactions["RECENT"] = {"ref": "RECENT", "status": "pending", "amountCents": 1,
                                                 "createdAt": int(time.time() * 1000)}
        self.emu.state.save()
        self.emu.stop()
        emu2 = self.make_emu()
        self.assertEqual(emu2.state.transactions["STALE"]["status"], "timeout")
        self.assertEqual(emu2.state.transactions["RECENT"]["status"], "pending")
        self.assertEqual(self.pay("STALE", 1000, token, emu2)[1]["status"], "approved")
        emu2.stop()
        emu3 = self.make_emu(fresh=True)
        self.assertEqual(self.pay("X", 1000, token, emu3)[:2], (401, {"error": "unknown token"}))


@unittest.skipUnless(os.name == "posix", "POSIX file modes")
class FilePermissionTests(unittest.TestCase):

    def test_state_and_token_files_are_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.umask(0o022)       # typical umask: would leave files world-readable
            try:
                state_dir = os.path.join(tmp, "state")
                state_file = os.path.join(state_dir, "terminal.json")
                emu = omni.Emulator(omni.Config(lan=False, state_file=state_file))
                emu.state.save()
                token_file = os.path.join(tmp, "tok", "device.json")
                omni.save_device_token(token_file, {"deviceToken": "secret", "cloudBase": "http://x"})
            finally:
                os.umask(old)
            self.assertEqual(os.stat(state_file).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(token_file).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(state_dir).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(os.path.dirname(token_file)).st_mode & 0o777, 0o700)
            self.assertEqual(sorted(os.listdir(state_dir)), ["terminal.json"])   # no temp leftovers


# ── Cloud half against a fake aslan-omni-api ──────────────────────────────────

DEVICE_TOKEN = "omni_dev_token_123"


class FakeCloud:
    """Serves /omni/* only; every device route checks the OMNI-TOKEN over the bare path."""

    def __init__(self, token: str = DEVICE_TOKEN) -> None:
        self.token = token
        self.events: queue.Queue = queue.Queue()
        self.results: list[tuple[str, bytes, dict]] = []    # accepted, first per commandId
        self.rejected: list[tuple[str, dict]] = []          # later posts for a completed command
        self.pings: list[bytes] = []
        self.initiates = 0
        self.stream_opens = 0
        self.pending_fetches = 0
        self.pending_command: dict | None = None
        self.auth_failures: list[str] = []
        self.unprefixed: list[str] = []
        self.demo_token: str | None = None
        self.claim_polls = 0
        self.stop = threading.Event()
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, status, obj):
                raw = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authed(self, path, body) -> bool:
                hdr = self.headers.get("Authorization", "")
                m = re.fullmatch(r"OMNI-TOKEN tokenId=([^,]+),ts=(\d+),sig=([0-9a-f]{64})", hdr)
                ok = False
                if m and m.group(1) == fake.token and abs(int(m.group(2)) - time.time()) <= 300:
                    msg = f"{m.group(1)}:{m.group(2)}:{self.command}:{path}:{hashlib.sha256(body).hexdigest()}"
                    ok = hmac.compare_digest(hmac.new(fake.token.encode(), msg.encode(), hashlib.sha256).hexdigest(),
                                             m.group(3))
                if not ok:
                    fake.auth_failures.append(f"{self.command} {path}")
                    self._json(401, {"error": "Invalid signature"})
                return ok

            def _route(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                if not self.path.startswith("/omni/"):
                    fake.unprefixed.append(self.path)
                    return self._json(404, {"error": "not found"})
                path = self.path[len("/omni"):]
                if path == "/devices/demo-token":
                    return self._json(200, {"deviceToken": fake.demo_token, "merchantName": "Demo"}) \
                        if fake.demo_token else self._json(404, {"errorCode": "NOT_FOUND"})
                if path == "/devices/claim":
                    fake.claim_body = json.loads(body)
                    return self._json(200, {"uuid": "u1", "claimUrl": "https://dash/omni/claim/u1"})
                if path == "/devices/claim/u1/status":
                    fake.claim_polls += 1
                    return self._json(200, {"status": "pending"} if fake.claim_polls < 2 else
                                      {"status": "activated", "deviceToken": fake.token, "merchantId": "m1"})
                if not self._authed(path, body):
                    return
                if path == "/cloud/pair/initiate":
                    fake.initiates += 1
                    return self._json(200, {"pairingCode": "ABCD1234", "qrToken": "ABCD1234", "expiresInSeconds": 120})
                if path == "/cloud/ping":
                    fake.pings.append(body)
                    return self._json(200, {"ok": True})
                if path == "/cloud/commands/pending":
                    fake.pending_fetches += 1
                    cmd, fake.pending_command = fake.pending_command, None
                    return self._json(200, {"command": cmd})
                m = re.fullmatch(r"/cloud/pay/([^/]+)/result", path)
                if m and self.command == "POST":
                    with fake.lock:     # cloud.ts: command.status !== "pending" → 409
                        if fake.result_for(m.group(1)) is not None:
                            fake.rejected.append((m.group(1), json.loads(body)))
                            return self._json(409, {"error": "Command already completed"})
                        fake.results.append((m.group(1), body, json.loads(body)))
                    return self._json(200, {"ok": True})
                if path == "/cloud/stream":
                    return self._stream()
                self._json(404, {"error": "not found"})

            def _stream(self):
                fake.stream_opens += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"retry: 3000\n\n: connected\n\n")
                self.wfile.flush()
                while not fake.stop.is_set():
                    try:
                        item = fake.events.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    if item == "CLOSE":
                        return
                    event, data = item
                    self.wfile.write(f"id: x\nevent: {event}\ndata: {json.dumps(data)}\n\n".encode())
                    self.wfile.flush()

            do_GET = do_POST = _route

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()

    def push(self, event: str, data: dict) -> None:
        self.events.put((event, data))

    def result_for(self, command_id: str):
        return next((r for r in self.results if r[0] == command_id), None)


class CloudTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmpdir = tmp.name
        self.fake = FakeCloud()
        self.addCleanup(self.fake.close)

    def start_device(self, base=None, pending=None, **cfg) -> omni.CloudDevice:
        self.fake.pending_command = pending
        emu = omni.Emulator(omni.Config(lan=False, state_file=os.path.join(self.tmpdir, "t.json"), **cfg))
        self.emu = emu
        dev = omni.CloudDevice(base or self.fake.base, DEVICE_TOKEN, emu, backoff_base=0.05, backoff_max=0.2)
        dev.start()
        self.addCleanup(dev.stop)
        self.assertTrue(wait_until(lambda: self.fake.stream_opens >= 1 and self.fake.pending_fetches >= 1))
        return dev

    def wait_result(self, command_id) -> tuple[str, bytes, dict]:
        self.assertTrue(wait_until(lambda: self.fake.result_for(command_id) is not None), command_id)
        return self.fake.result_for(command_id)

    def tearDown(self):
        self.assertEqual(self.fake.auth_failures, [])
        self.assertEqual(self.fake.unprefixed, [])

    def test_pair_initiate_and_prefix(self):
        dev = self.start_device()
        self.assertTrue(wait_until(lambda: dev.pairing_code == "ABCD1234"))
        dev.initiate_pairing()                      # console "p"
        self.assertEqual(self.fake.initiates, 2)

    def test_base_already_ending_in_omni_is_not_doubled(self):
        self.start_device(base=self.fake.base + "/omni/")
        self.assertTrue(wait_until(lambda: self.fake.initiates == 1))

    def test_pending_command_on_connect_and_result_payload(self):
        self.start_device(pending={"commandId": "cmd-p", "ref": "PEND-1", "amountCents": 2000, "cashierId": "c"},
                          terminal_id="TID9", merchant_id="MID9")
        _, raw, body = self.wait_result("cmd-p")
        self.assertEqual(set(body), {"status", "responseCode", "authNumber", "stan", "cardNumber", "cardScheme",
                                     "txDate", "txTime", "acquirerMerchantId", "acquirerTerminalId",
                                     "transactionNumber"})
        self.assertEqual((body["status"], body["responseCode"], body["acquirerTerminalId"],
                          body["acquirerMerchantId"]), ("approved", "000", "TID9", "MID9"))
        self.assertIn(b"\\/", raw)                   # Android org.json escapes '/'
        self.assertEqual(self.emu.state.transactions["PEND-1"]["status"], "approved")

    def test_sse_pay_ping_and_outcomes(self):
        self.start_device()
        self.fake.push("Ping", {"seq": 1})
        self.fake.push("PayCommand", {"commandId": "c-dec", "ref": "DEC", "amountCents": 1005})
        self.fake.push("PayCommand", {"commandId": "c-tmo", "ref": "TMO", "amountCents": 1051})
        self.fake.push("PayCommand", {"commandId": "c-can", "ref": "CAN", "amountCents": 1008})
        self.fake.push("BrandingUpdated", {})
        self.fake.push("PairingRevoked", {})
        self.assertEqual(self.wait_result("c-dec")[2], {"status": "declined", "responseCode": "005"})
        self.assertEqual(self.wait_result("c-tmo")[2], {"status": "timeout"})
        self.assertEqual(self.wait_result("c-can")[2], {"status": "cancelled", "responseCode": "099"})
        self.assertTrue(wait_until(lambda: self.fake.pings == [b"{}"]))

    def test_redelivered_command_is_reposted_not_recharged(self):
        self.start_device()
        self.fake.push("PayCommand", {"commandId": "c1", "ref": "DUP", "amountCents": 1000})
        first = self.wait_result("c1")[2]
        self.fake.push("PayCommand", {"commandId": "c2", "ref": "DUP", "amountCents": 1000})
        second = self.wait_result("c2")[2]
        self.assertEqual(second["stan"], first["stan"])
        self.assertEqual(second["status"], "approved")
        self.assertNotIn("transactionNumber", second)   # not stored on the terminal
        self.fake.push("PayCommand", {"commandId": "c3", "ref": "T2", "amountCents": 1051})
        self.wait_result("c3")
        self.fake.push("PayCommand", {"commandId": "c4", "ref": "T2", "amountCents": 1051})
        self.assertEqual(self.wait_result("c4")[2], {"status": "timeout"})

    def test_invalid_commands_dropped(self):
        self.start_device()
        self.fake.push("PayCommand", {"commandId": "bad1", "ref": "Z", "amountCents": 0})
        self.fake.push("PayCommand", {"commandId": "", "ref": "Z", "amountCents": 1000})
        self.fake.push("PayCommand", {"commandId": "bad3", "amountCents": 1000})
        self.fake.push("ReverseCommand", {"commandId": "bad4", "ref": "R"})
        self.fake.push("PayCommand", {"commandId": "good", "ref": "G", "amountCents": 1000})
        self.wait_result("good")
        time.sleep(0.2)
        self.assertEqual([r[0] for r in self.fake.results], ["good"])

    def test_overlapping_deliveries_share_the_first_result(self):
        self.start_device(delay=0.3)
        # Same command re-delivered while the card is still being read (SSE vs pending fetch).
        self.fake.push("PayCommand", {"commandId": "same", "ref": "OVL", "amountCents": 1000})
        self.fake.push("PayCommand", {"commandId": "same", "ref": "OVL", "amountCents": 1000})
        self.fake.push("PayCommand", {"commandId": "other", "ref": "OVL", "amountCents": 1000})
        first = self.wait_result("same")[2]
        other = self.wait_result("other")[2]
        self.assertEqual(first["status"], "approved")          # no DUPLICATE decline won the race
        self.assertEqual((other["status"], other["stan"]), ("approved", first["stan"]))
        self.assertTrue(wait_until(lambda: len(self.fake.rejected) == 1))
        self.assertEqual(self.fake.rejected[0][1]["stan"], first["stan"])
        self.assertNotIn("DUPLICATE", json.dumps([r[2] for r in self.fake.results] + self.fake.rejected))

    def test_stop_cancels_in_flight_payment(self):
        dev = self.start_device(delay=30)
        self.fake.push("PayCommand", {"commandId": "slow", "ref": "SLOW", "amountCents": 1000})
        self.assertTrue(wait_until(lambda: "SLOW" in self.emu.engine._inflight))
        t0 = time.time()
        dev.stop()
        self.assertLess(time.time() - t0, 3)
        self.assertEqual(dev._workers, set())                  # every handler joined
        self.fake.push("PayCommand", {"commandId": "late", "ref": "LATE", "amountCents": 1000})
        time.sleep(0.3)
        self.assertEqual(self.fake.results, [])
        self.assertNotIn("SLOW", self.emu.state.transactions)
        self.assertNotIn("LATE", self.emu.state.transactions)

    def test_reverse_command(self):
        self.start_device()
        self.fake.push("ReverseCommand", {"commandId": "r1", "ref": "REV", "originalRef": "X", "stan": "123456"})
        body = self.wait_result("r1")[2]
        self.assertEqual((body["status"], body["responseCode"]), ("reversed", "000"))

    def test_reverse_command_declined_and_timeout(self):
        self.start_device(mode="reversal_decline", code="912")
        self.fake.push("ReverseCommand", {"commandId": "r1", "ref": "REV", "originalRef": "X", "stan": "1"})
        self.assertEqual(self.wait_result("r1")[2], {"status": "declined", "responseCode": "912"})
        self.emu.cfg.mode, self.emu.cfg.timeout_after = "reversal_timeout", 0.05
        self.fake.push("ReverseCommand", {"commandId": "r2", "ref": "REV2", "originalRef": "X", "stan": "1"})
        self.assertEqual(self.wait_result("r2")[2], {"status": "timeout"})

    def test_reconnects_and_refetches_pending(self):
        self.start_device()
        self.fake.pending_command = {"commandId": "after", "ref": "AFTER", "amountCents": 1000}
        self.fake.events.put("CLOSE")
        self.assertTrue(wait_until(lambda: self.fake.stream_opens >= 2))
        self.wait_result("after")
        self.fake.push("PayCommand", {"commandId": "live", "ref": "LIVE", "amountCents": 1000})
        self.wait_result("live")


class TokenAcquisitionTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.token_file = os.path.join(tmp.name, "device.json")
        self.fake = FakeCloud()
        self.addCleanup(self.fake.close)
        self.cfg = omni.Config(lan=False, serial="SER-1")

    def test_claim_flow_persists_token(self):
        token = omni.acquire_device_token(self.fake.base, self.cfg, self.token_file, poll_sec=0.01)
        self.assertEqual(token, DEVICE_TOKEN)
        self.assertEqual(self.fake.claim_body, {"serialNumber": "SER-1", "model": "P3", "appVersion": "1.3.5"})
        with open(self.token_file) as fh:
            self.assertEqual(json.load(fh)["deviceToken"], DEVICE_TOKEN)
        polls = self.fake.claim_polls
        self.assertEqual(omni.acquire_device_token(self.fake.base + "/omni", self.cfg, self.token_file), DEVICE_TOKEN)
        self.assertEqual(self.fake.claim_polls, polls)   # cache hit (same API root)

    def test_demo_token_and_explicit_token(self):
        self.fake.demo_token = "demo-tok"
        self.assertEqual(omni.acquire_device_token(self.fake.base, self.cfg, self.token_file), "demo-tok")
        self.assertEqual(omni.acquire_device_token(self.fake.base, self.cfg, self.token_file, explicit="mine"), "mine")
        self.assertEqual(self.fake.unprefixed, [])


if __name__ == "__main__":
    unittest.main()
