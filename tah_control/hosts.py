"""Only modify the explicitly marked hosts entry. No global proxy changes."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HOST = "speedtest.jsqiuying.com"
ENTRY = "127.0.0.1 speedtest.jsqiuying.com # iota-local-speedtest\n"


def transform(text: str, action: str) -> str:
    if action not in {"install", "remove"}:
        raise ValueError("unsupported hosts action")
    lines = text.splitlines(keepends=True)
    for line in lines:
        fields = line.split("#", 1)[0].split()
        if HOST in fields[1:] and line != ENTRY:
            raise ValueError("existing hosts mapping conflicts; inspect /etc/hosts")
    result = "".join(line for line in lines if line != ENTRY)
    if action == "remove":
        return result
    return result + ("" if not result or result.endswith("\n") else "\n") + ENTRY


def apply(action: str, path: Path = Path("/etc/hosts")) -> bool:
    if os.geteuid() != 0:
        raise PermissionError("hosts editing requires administrator privileges")
    # Do not follow symlinks outside /etc: explicit trusted system target only.
    path = path.resolve(strict=True)
    before = path.read_text()
    after = transform(before, action)
    if after == before:
        return False
    backup = path.with_name("hosts.iota-local-speedtest.backup")
    if not backup.exists():
        shutil.copy2(path, backup)
    metadata = path.stat()
    fd, name = tempfile.mkstemp(prefix=".hosts-iota-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, metadata.st_mode & 0o777)
        os.chown(name, metadata.st_uid, metadata.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    if path == Path("/etc/hosts").resolve():
        subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], check=True)
        subprocess.run(["/usr/bin/killall", "-HUP", "mDNSResponder"], check=True)
    return True
