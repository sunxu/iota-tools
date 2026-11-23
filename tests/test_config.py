import tempfile
from pathlib import Path
import unittest

from tah_control.config import load_settings


class SettingsTests(unittest.TestCase):
    def test_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = load_settings(Path(tmp) / "missing.toml")
        self.assertEqual(settings.section("proxy")["port"], 8899)
        self.assertEqual(settings.section("r2", "upload")["max_concurrency"], 5)
        self.assertEqual(settings.section("r2", "download")["max_concurrent_takeovers"], 16)
        self.assertEqual(settings.section("r2", "download")["slow_threshold_kib_s"], 500)
        self.assertEqual(settings.section("r2", "download")["direct_takeover_threshold_mib"], 24)
        self.assertIs(settings.section("r2", "download")["capture_requests"], True)

    def test_override_and_unknown_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "local.toml"
            p.write_text("[r2.upload]\nmax_concurrency=3\n")
            self.assertEqual(load_settings(p).section("r2", "upload")["max_concurrency"], 3)
            p.write_text("[r2.upload]\nnot_a_real_field=4\n")
            with self.assertRaisesRegex(ValueError, "unknown"):
                load_settings(p)

    def test_download_override_and_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "local.toml"
            p.write_text('[r2.download]\nmax_concurrent_takeovers=12\nreplacement_proxy="http://127.0.0.1:7894"\n')
            settings = load_settings(p)
            self.assertEqual(settings.section("r2", "download")["max_concurrent_takeovers"], 12)
            self.assertEqual(settings.section("r2", "download")["replacement_proxy"], "http://127.0.0.1:7894")
            p.write_text("[r2.download]\ndirect_takeover_threshold_mib=32\n")
            self.assertEqual(load_settings(p).section("r2", "download")["direct_takeover_threshold_mib"], 32)
            p.write_text("[r2.download]\ncapture_requests=false\n")
            self.assertIs(load_settings(p).section("r2", "download")["capture_requests"], False)
            for invalid in (
                "[r2.download]\nmax_concurrent_takeovers=0\n",
                "[r2.download]\nslow_threshold_kib_s=0\n",
                "[r2.download]\nslow_window_seconds=0\n",
                "[r2.download]\nmax_concurrent_takeovers=-1\n",

                "[r2.download]\ndirect_takeover_threshold_mib=0\n",
                "[r2.download]\ndirect_takeover_threshold_mib=-1\n",
                "[r2.download]\ndirect_takeover_threshold_mib=1.5\n",
                '[r2.download]\ncapture_requests="true"\n',
                '[r2.download]\nreplacement_proxy="http://10.0.0.1:7893"\n',
            ):
                p.write_text(invalid)
                with self.assertRaises(ValueError):
                    load_settings(p)

    def test_values_above_previous_fixed_maxima(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "local.toml"
            for section, key, value in (
                ("r2.upload", "max_concurrency", 101),
                ("r2.upload", "fallback_max_concurrency", 101),
                ("r2.download", "max_concurrent_takeovers", 65),
                ("r2.download", "slow_threshold_kib_s", 100001),
                ("r2.download", "slow_window_seconds", 121),
            ):
                with self.subTest(section=section, key=key):
                    p.write_text(f"[{section}]\\n{key}={value}\\n")
                    self.assertEqual(load_settings(p).section(*section.split("."))[key], value)

    def test_schema_and_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "local.toml"
            for invalid in ("schema_version=2\n", "[r2.upload]\nmax_concurrency=0\n",
                            "[r2.upload]\nfallback_max_concurrency=0\n",
                            "[proxy]\nport=8877\n", "[speedtest]\nmbps=1000\n"):
                p.write_text(invalid)
                with self.assertRaises(ValueError):
                    load_settings(p)

    def test_reject_proxy_to_non_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "local.toml"
            p.write_text('[r2.upload]\nprimary_proxy="http://10.0.0.1:18585"\n')
            with self.assertRaisesRegex(ValueError, "127.0.0.1"):
                load_settings(p)


if __name__ == "__main__":
    unittest.main()
