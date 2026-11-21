"""Pure R2 request predicates; never decode or rewrite signed URLs."""
import re
from urllib.parse import parse_qs, urlsplit


_R2_SUFFIX = ".r2.cloudflarestorage.com"
_LIST_OR_MANAGEMENT_QUERY_KEYS = {
    "acl", "analytics", "continuation-token", "cors", "delete", "delimiter",
    "encoding-type", "encryption", "fetch-owner", "inventory", "legal-hold",
    "lifecycle", "list-type", "location", "logging", "marker", "max-keys",
    "metrics", "notification", "object-lock", "ownershipcontrols", "partnumber",
    "policy", "prefix", "publicaccessblock", "replication", "requestpayment",
    "restore", "start-after", "tagging", "torrent", "uploadid", "uploads",
    "versions", "versioning", "website",
}


def is_upload_part(method: str, host: str, url: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if method.upper() != "PUT" or not host.endswith(_R2_SUFFIX):
        return False
    qs = parse_qs(urlsplit(url).query, keep_blank_values=True)
    upload_id = qs.get("uploadId", [])
    part = qs.get("partNumber", [])
    if (len(upload_id) != 1 or not upload_id[0] or len(part) != 1
            or not re.fullmatch(r"[0-9]+", part[0], re.ASCII)):
        return False
    try:
        return 1 <= int(part[0]) <= 10000
    except ValueError:
        return False


def is_r2_object_get(method: str, host: str, url: str, headers=None) -> bool:
    """Match HTTPS S3 object GETs, excluding path-style bucket listings and management APIs."""
    host = (host or "").lower().rstrip(".")
    if method.upper() != "GET" or not host.endswith(_R2_SUFFIX):
        return False
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or parsed.path in ("", "/"):
        return False

    # R2 supports path-style ACCOUNT_ID/bucket/key and virtual-hosted bucket.ACCOUNT_ID/key.
    # A one-label endpoint with only /bucket is a bucket listing, not an object download.
    endpoint_prefix = host[:-len(_R2_SUFFIX)]
    path_segments = [piece for piece in parsed.path.split("/") if piece]
    if "." not in endpoint_prefix and len(path_segments) < 2:
        return False

    query = parse_qs(parsed.query, keep_blank_values=True)
    if any(key.lower() in _LIST_OR_MANAGEMENT_QUERY_KEYS for key in query):
        return False
    if headers is not None:
        range_value = headers.get("range", "")
        if "," in range_value:
            return False
        if headers.get("content-length", "0") not in ("", "0"):
            return False
        if headers.get("transfer-encoding"):
            return False
    return True
