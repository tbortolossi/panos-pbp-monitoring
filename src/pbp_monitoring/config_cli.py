"""Initialize or migrate the persistent PBP Monitoring configuration."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from .config_store import ConfigStore
from .orchestrator import load_target_profiles


ENV_SETTING_MAP = {
    "POLL_SECONDS": "poll_seconds",
    "MAX_MONITOR_SECONDS": "max_monitor_seconds",
    "INCIDENT_IDLE_TTL_SECONDS": "incident_idle_ttl_seconds",
    "RECOVERY_THRESHOLD": "recovery_threshold",
    "LOW_SAMPLES_TO_STOP": "low_samples_to_stop",
    "REQUEST_TIMEOUT": "request_timeout",
    "MAX_SESSION_LOOKUPS": "max_session_lookups",
    "SESSION_RETRY_SECONDS": "session_retry_seconds",
    "GENERATE_HTML_REPORT": "generate_html_report",
    "GENERATE_TEXT_EXPORT": "generate_text_export",
}


def import_legacy(store: ConfigStore, targets_file: Path, env_file: Path | None) -> int:
    store.initialize()
    if store.list_targets():
        raise ValueError("persistent configuration already contains firewalls")
    if env_file is not None:
        _load_legacy_env(env_file)
    profiles = load_target_profiles(targets_file)
    settings = {
        setting: os.environ[environment]
        for environment, setting in ENV_SETTING_MAP.items()
        if environment in os.environ
    }
    if settings:
        store.update_settings(settings)
    for profile in profiles:
        store.save_target(
            name=profile.name,
            panos_url=profile.panos_url,
            api_key=profile.api_key,
            target_serial=profile.target_serial,
            serials=profile.serials,
            syslog_sources=profile.syslog_sources,
            tls_verify=str(profile.tls_verify).lower() if isinstance(profile.tls_verify, bool) else profile.tls_verify,
        )
    return len(profiles)


def _load_legacy_env(path: Path) -> None:
    """Load legacy Docker env semantics: the last duplicate value wins."""
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"{path}:{line_number}: invalid environment variable name")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'\"', "'"}:
            value = value[1:-1]
        os.environ[name] = value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-db", type=Path, default=Path(os.getenv("PBP_CONFIG_DB", "/config/config.db")))
    subparsers = parser.add_subparsers(dest="command", required=True)
    initialize = subparsers.add_parser("init", help="initialize an empty persistent store")
    del initialize
    migrate = subparsers.add_parser("import-legacy", help="one-time import from targets.json and .env")
    migrate.add_argument("--targets", type=Path, required=True)
    migrate.add_argument("--env-file", type=Path)
    args = parser.parse_args(argv)
    store = ConfigStore(args.config_db)
    try:
        if args.command == "init":
            store.initialize()
            print(f"Configuration initialized at {args.config_db}")
        else:
            count = import_legacy(store, args.targets, args.env_file)
            print(f"Imported {count} firewall(s) into encrypted persistent configuration")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Configuration error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
