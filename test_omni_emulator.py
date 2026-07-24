import unittest
import omni_emulator as e


class ScenarioTests(unittest.TestCase):
    def test_resolve_code_by_name_and_number(self):
        self.assertEqual(e.resolve_code("insufficient_funds"), "116")
        self.assertEqual(e.resolve_code("116"), "116")
        self.assertEqual(e.resolve_code("909"), "909")  # unknown numeric passes through

    def test_magic_amount_overrides(self):
        self.assertEqual(e.magic_outcome(1000), "approved")   # ..00
        self.assertEqual(e.magic_outcome(1005), "declined")   # ..05
        self.assertEqual(e.magic_outcome(1008), "cancelled")  # ..08
        self.assertEqual(e.magic_outcome(1051), "timeout")    # ..51
        self.assertIsNone(e.magic_outcome(1042))              # no magic suffix


class HmacTests(unittest.TestCase):
    def test_sha256_hex_empty(self):
        self.assertEqual(
            e.sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_lan_derived_key_roundtrip(self):
        # Terminal: tokenHmac = HMAC(tokenSecret_bytes, tokenId); key = hexToBytes(tokenHmac).
        token_secret = bytes.fromhex("00112233445566778899aabbccddeeff")
        token_id = "tok-1"
        token_hmac = e.hmac_hex(token_secret, token_id.encode())      # stored on "terminal"
        # A client signs; the emulator must recompute the same sig with the derived key.
        ts, method, path, body = "1700000000", "POST", "/pay", b'{"a":1}'
        msg = f"{token_id}:{ts}:{method}:{path}:{e.sha256_hex(body)}"
        client_sig = e.hmac_hex(bytes.fromhex(token_hmac), msg.encode())
        expected = e.lan_expected_sig(token_hmac, token_id, ts, method, path, body)
        self.assertEqual(client_sig, expected)

    def test_cloud_device_sig_uses_raw_token_key(self):
        device_token = "omni_deadbeef"
        ts, method, path, body = "1700000000", "GET", "/cloud/stream", b""
        sig = e.device_sig(device_token, ts, method, path, body)
        # Independently recompute: key = deviceToken utf-8, msg includes the token.
        msg = f"{device_token}:{ts}:{method}:{path}:{e.sha256_hex(body)}"
        self.assertEqual(sig, e.hmac_hex(device_token.encode(), msg.encode()))


class OutcomeTests(unittest.TestCase):
    def test_approved_has_auth_fields(self):
        o = e.decide_outcome(1000, mode="approve", error_code="909")  # magic ..00
        self.assertEqual(o["status"], "approved")
        self.assertEqual(o["responseCode"], "000")
        self.assertRegex(o["stan"], r"^\d{6}$")
        self.assertRegex(o["authNumber"], r"^\d{6}$")
        self.assertTrue(o["cardNumber"].startswith("5"))
        self.assertEqual(o["cardScheme"], "MASTERCARD")

    def test_magic_beats_mode(self):
        # amount forces declined even though mode=approve
        o = e.decide_outcome(1005, mode="approve", error_code="909")
        self.assertEqual(o["status"], "declined")

    def test_error_mode_uses_code(self):
        o = e.decide_outcome(1042, mode="error", error_code="insufficient_funds")
        self.assertEqual(o["status"], "declined")
        self.assertEqual(o["responseCode"], "116")

    def test_timeout_and_cancelled(self):
        self.assertEqual(e.decide_outcome(1051, "approve", "909")["status"], "timeout")
        self.assertEqual(e.decide_outcome(1008, "approve", "909")["status"], "cancelled")

    def test_pay_result_shape(self):
        o = e.decide_outcome(1000, "approve", "909")
        r = e.pay_result("ORDER-1", 1000, o)
        self.assertEqual(r["ref"], "ORDER-1")
        self.assertEqual(r["amountCents"], 1000)
        self.assertEqual(r["status"], "approved")
        self.assertIn("transactionDate", r)


class PairingTests(unittest.TestCase):
    def test_pair_request_then_confirm_issues_token(self):
        store = e.PairingStore()
        session_id, pin = store.begin("TILL-01", "Caisse 1")
        self.assertRegex(pin, r"^\d{6}$")
        tok = store.confirm(session_id, pin, "TILL-01", "Caisse 1")
        self.assertIn("tokenId", tok)
        self.assertRegex(tok["tokenSecret"], r"^[0-9a-f]{64}$")
        self.assertEqual(tok["terminalModel"], "P3")

    def test_confirm_wrong_pin(self):
        store = e.PairingStore()
        session_id, _pin = store.begin("T", "L")
        with self.assertRaises(e.PairError):
            store.confirm(session_id, "000000", "T", "L")

    def test_verify_signed_request_accepts_client_sig(self):
        store = e.PairingStore()
        sid, pin = store.begin("T", "L")
        tok = store.confirm(sid, pin, "T", "L")
        token_id, secret_hex = tok["tokenId"], tok["tokenSecret"]
        derived = e.hmac_hex(bytes.fromhex(secret_hex), token_id.encode())
        ts = str(int(e.time.time()))
        body = b'{"ref":"R1","amountCents":1000}'
        sig = e.hmac_hex(bytes.fromhex(derived), f"{token_id}:{ts}:POST:/pay:{e.sha256_hex(body)}".encode())
        ok, err = store.verify(token_id, ts, "POST", "/pay", body, sig)
        self.assertTrue(ok, err)

    def test_verify_rejects_bad_sig_and_skew(self):
        store = e.PairingStore()
        sid, pin = store.begin("T", "L")
        tok = store.confirm(sid, pin, "T", "L")
        ts = str(int(e.time.time()))
        ok, err = store.verify(tok["tokenId"], ts, "POST", "/pay", b"{}", "deadbeef")
        self.assertFalse(ok)
        old = str(int(e.time.time()) - 999)
        ok2, _ = store.verify(tok["tokenId"], old, "POST", "/pay", b"{}", "x")
        self.assertFalse(ok2)

    def test_list_and_revoke(self):
        store = e.PairingStore()
        sid, pin = store.begin("TILL-9", "Caisse 9")
        tok = store.confirm(sid, pin, "TILL-9", "Caisse 9")
        rows = store.list_pos()
        self.assertEqual(rows[0]["posId"], "TILL-9")
        self.assertIn("createdAt", rows[0])
        self.assertTrue(store.revoke(tok["tokenId"]))
        self.assertEqual(store.list_pos(), [])


if __name__ == "__main__":
    unittest.main()
