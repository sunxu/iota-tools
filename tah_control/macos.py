"""User LaunchAgent registration and a no-Terminal Finder entrypoint."""
from __future__ import annotations

import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import tempfile

from tah_control.config import ROOT, Settings, ensure_runtime

LABEL = "com.sunxu.iota-tools.supervisor"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / (LABEL + ".plist")


def domain() -> str:
    return f"gui/{os.getuid()}"


def ensure_macos() -> None:
    if sys.platform != "darwin":
        raise RuntimeError("LaunchAgent management requires macOS and a logged-in GUI session")


def install(settings: Settings) -> Path:
    ensure_macos()
    runtime = ensure_runtime(settings)
    agent = plist_path()
    agent.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, "-m", "tah_control.cli", "run"],
        "WorkingDirectory": str(ROOT),
        "EnvironmentVariables": {"PYTHONPATH": str(ROOT), "IOTA_TOOLS_CONFIG": str(settings.source)},
        "RunAtLoad": True,
        "KeepAlive": True,
        "LimitLoadToSessionType": "Aqua",
        "StandardOutPath": str(runtime / "supervisor.stdout.log"),
        "StandardErrorPath": str(runtime / "supervisor.stderr.log"),
        "ThrottleInterval": 10,
    }
    # Avoid silently taking ownership of a different user-managed agent.
    if agent.exists():
        existing = plistlib.loads(agent.read_bytes())
        if existing.get("Label") != LABEL:
            raise RuntimeError("unexpected LaunchAgent at target path")
        subprocess.run(["launchctl", "bootout", domain() + "/" + LABEL], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    agent.write_bytes(plistlib.dumps(payload))
    subprocess.run(["launchctl", "bootstrap", domain(), str(agent)], check=True)
    return agent


def uninstall() -> None:
    ensure_macos()
    agent = plist_path()
    subprocess.run(["launchctl", "bootout", domain() + "/" + LABEL],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    agent.unlink(missing_ok=True)


def kickstart(restart: bool = False) -> None:
    ensure_macos()
    cmd = ["launchctl", "kickstart"]
    if restart:
        cmd.append("-k")  # Controlled restart of the Supervisor and its owned helpers.
    cmd.append(domain() + "/" + LABEL)
    subprocess.run(cmd, check=True)


def install_finder_app() -> Path:
    """Build a small Finder launcher; not a replacement for the original IOTA app."""
    ensure_macos()
    folder = Path.home() / "Applications"
    folder.mkdir(exist_ok=True)
    output = folder / "IOTA Managed.app"
    # AppleScript do shell script executes the intended command, without opening Terminal.
    cmd = "cd " + shlex.quote(str(ROOT)) + " && " + shlex.quote(sys.executable) + \
        " -m tah_control.cli start"
    script = 'on run\n    do shell script ' + '"' + cmd.replace("\\", "\\\\").replace('"', '\\"') + '"\nend run\n'
    with tempfile.TemporaryDirectory() as tmp:
        script_path = Path(tmp) / "launcher.applescript"
        script_path.write_text(script)
        subprocess.run(["/usr/bin/osacompile", "-o", str(output), str(script_path)], check=True)
    return output
