import unittest
from tah_control.hosts import transform, ENTRY


class HostsTests(unittest.TestCase):
    def test_install_idempotent_and_reversible(self):
        original = "127.0.0.1 localhost\n"
        once = transform(original, "install")
        self.assertIn(ENTRY, once)
        self.assertEqual(transform(once, "install"), once)
        self.assertEqual(transform(once, "remove"), original)

    def test_conflict_rejected(self):
        with self.assertRaisesRegex(ValueError, "conflicts"):
            transform("10.0.0.2 speedtest.jsqiuying.com\n", "install")


if __name__ == "__main__":
    unittest.main()
