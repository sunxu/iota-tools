"""Pure R2 UploadPart predicate; never decode or rewrite signed URLs."""
import re
from urllib.parse import parse_qs, urlsplit


def is_upload_part(method: str, host: str, url: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if method.upper() != "PUT" or not host.endswith(".r2.cloudflarestorage.com"):
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
