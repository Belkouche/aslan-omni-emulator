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


if __name__ == "__main__":
    unittest.main()
