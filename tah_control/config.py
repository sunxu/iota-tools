"""Versioned, validated configuration with an optional machine-local override."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import os
import tomllib
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "defaults.toml"
LOCAL_CONFIG = Path.home() / ".config" / "iota-tools" / "config.toml"


def _merge(base: dict, override: dict, prefix: str = "") -> None:
    for key, value in override.items():
        where = prefix + key
        if key not in base:
            raise ValueError(f"unknown config key: {where}")
        original = base[key]
        if isinstance(original, dict):
            if not isinstance(value, dict):
                raise ValueError(f"{where} must be a section")
            _merge(original, value, where + ".")
        elif type(original) is not type(value):
            if not (type(original) is int and type(value) is float):
                raise ValueError(f"wrong type for {where}")
            base[key] = value
        else:
            base[key] = value


def _port(value: object, name: str) -> None:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{name} must be a TCP port")


def _proxy_url(value: str, name: str) -> None:
    u = urlsplit(value)
    if (u.scheme != "http" or u.username or u.password or u.path
            or u.query or u.fragment or u.hostname != "127.0.0.1" or not u.port):
        raise ValueError(f"{name} must be an http://127.0.0.1:PORT proxy URL")


@dataclass(frozen=True)
class Settings:
    data: dict
    source: Path

    def section(self, *keys: str) -> dict:
        value = self.data
        for key in keys:
            value = value[key]
        return value

    @property
    def runtime(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "iota-tools"

    @property
    def app(self) -> Path:
        return Path(self.data["app"]["path"]).expanduser()

    def validate(self) -> None:
        d = self.data
        if d["schema_version"] != 1:
            raise ValueError("unsupported schema_version, expected 1")
        _port(d["proxy"]["port"], "proxy.port")
        _port(d["speedtest"]["port"], "speedtest.port")
        if d["proxy"]["port"] == d["speedtest"]["port"]:
            raise ValueError("proxy and speedtest ports must differ")
        if d["speedtest"]["host"] != "speedtest.jsqiuying.com":
            raise ValueError("speedtest.host must match the pinned local XML")
        mbps = d["speedtest"]["mbps"]
        if type(mbps) not in (int, float) or not 200 <= mbps <= 500:
            raise ValueError("speedtest.mbps must be between 200 and 500")
        for name in ("scan_seconds", "update_grace_seconds", "restart_delay_seconds",
                     "max_restarts_per_hour"):
            value = d["supervisor"][name]
            if type(value) not in (int, float) or value <= 0:
                raise ValueError(f"supervisor.{name} must be positive")
        if type(d["supervisor"]["max_restarts_per_hour"]) is not int:
            raise ValueError("supervisor.max_restarts_per_hour must be an integer")
        up = d["r2"]["upload"]
        for name in ("primary_proxy", "fallback_proxy"):
            _proxy_url(up[name], "r2.upload." + name)
        if up["primary_proxy"] == up["fallback_proxy"]:
            raise ValueError("primary and fallback must differ")
        for name in ("max_concurrency", "fallback_max_concurrency"):
            if type(up[name]) is not int or up[name] < 1:
                raise ValueError(f"r2.upload.{name} out of range")
        for name in ("probe_interval_seconds", "probe_timeout_seconds"):
            if type(up[name]) not in (int, float) or up[name] <= 0:
                raise ValueError(f"r2.upload.{name} must be positive")

        down = d["r2"]["download"]
        if type(down["enabled"]) is not bool:
            raise ValueError("r2.download.enabled must be boolean")
        if (type(down["slow_threshold_kib_s"]) is not int
                or down["slow_threshold_kib_s"] < 1):
            raise ValueError("r2.download.slow_threshold_kib_s out of range")
        if (type(down["slow_window_seconds"]) is not int
                or down["slow_window_seconds"] < 1):
            raise ValueError("r2.download.slow_window_seconds out of range")
        if (type(down["direct_takeover_threshold_mib"]) is not int
                or down["direct_takeover_threshold_mib"] <= 0):
            raise ValueError("r2.download.direct_takeover_threshold_mib must be a positive integer")
        if type(down["capture_requests"]) is not bool:
            raise ValueError("r2.download.capture_requests must be boolean")
        _proxy_url(down["replacement_proxy"], "r2.download.replacement_proxy")
        if (type(down["max_concurrent_takeovers"]) is not int
                or down["max_concurrent_takeovers"] < 1):
            raise ValueError("r2.download.max_concurrent_takeovers must be a positive integer")
        if not self.app.is_absolute():
            raise ValueError("app.path must be absolute")


def load_settings(local: Path | None = None) -> Settings:
    with DEFAULT_CONFIG.open("rb") as f:
        defaults = tomllib.load(f)
    local = local or Path(os.getenv("IOTA_TOOLS_CONFIG", str(LOCAL_CONFIG))).expanduser()
    data = deepcopy(defaults)
    if local.is_file():
        with local.open("rb") as f:
            _merge(data, tomllib.load(f))
    settings = Settings(data, local)
    settings.validate()
    return settings


def ensure_runtime(settings: Settings) -> Path:
    """Owner-only state; never store secrets in the Git worktree."""
    previous = os.umask(0o077)
    try:
        settings.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        settings.runtime.chmod(0o700)
    finally:
        os.umask(previous)
    return settings.runtime
