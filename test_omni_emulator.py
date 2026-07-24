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


if __name__ == "__main__":
    unittest.main()
