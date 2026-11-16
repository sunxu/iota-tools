import unittest
from multidict import CIMultiDict

from r2_client.eligibility import is_r2_object_get


ACCOUNT_HOST = "1234567890abcdef.r2.cloudflarestorage.com"
VIRTUAL_HOST = "assets.1234567890abcdef.r2.cloudflarestorage.com"


class R2GetEligibilityTests(unittest.TestCase):
    def test_path_style_object_and_bucket_listing(self):
        self.assertTrue(is_r2_object_get("GET", ACCOUNT_HOST,
                                         f"https://{ACCOUNT_HOST}/bucket/object"))
        self.assertFalse(is_r2_object_get("GET", ACCOUNT_HOST,
                                          f"https://{ACCOUNT_HOST}/bucket"))

    def test_virtual_hosted_object(self):
        self.assertTrue(is_r2_object_get("GET", VIRTUAL_HOST,
                                         f"https://{VIRTUAL_HOST}/object"))

    def test_management_queries_are_excluded(self):
        for query in ("list-type=2", "prefix=folder", "delimiter=%2F",
                      "uploadId=abc", "uploads", "versions"):
            self.assertFalse(is_r2_object_get(
                "GET", ACCOUNT_HOST, f"https://{ACCOUNT_HOST}/bucket?{query}"
            ))

    def test_signed_object_queries_and_version_id_are_allowed(self):
        url = f"https://{ACCOUNT_HOST}/bucket/folder%2Ffile?X-Amz-Signature=abc&versionId=v1"
        self.assertTrue(is_r2_object_get("GET", ACCOUNT_HOST, url))

    def test_only_https_single_range_object_gets(self):
        self.assertFalse(is_r2_object_get("GET", ACCOUNT_HOST,
                                          f"http://{ACCOUNT_HOST}/bucket/object"))
        self.assertFalse(is_r2_object_get(
            "GET", ACCOUNT_HOST, f"https://{ACCOUNT_HOST}/bucket/object",
            CIMultiDict({"Range": "bytes=0-1,5-8"}),
        ))
        self.assertFalse(is_r2_object_get("HEAD", ACCOUNT_HOST,
                                          f"https://{ACCOUNT_HOST}/bucket/object"))


if __name__ == "__main__":
    unittest.main()
