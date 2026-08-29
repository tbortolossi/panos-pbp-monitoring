#!/usr/bin/env python3
"""Interactively generate a PAN-OS XML API key."""

from __future__ import annotations

import argparse
import getpass
import ssl
import sys
from pathlib import Path
from urllib.request import urlopen

from pbp_monitoring.panos_keygen import (
    KeyGenerationError,
    generate_api_key as _generate_api_key,
    make_ssl_context,
    normalize_firewall_url,
)


def generate_api_key(*args, **kwargs):
    """Compatibility wrapper retaining the tool's mockable network boundary."""
    return _generate_api_key(*args, opener=urlopen, **kwargs)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a PAN-OS API key from interactive credentials."
    )
    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument(
        "--ca-bundle",
        type=Path,
        help="PEM bundle for the internal CA that signed the firewall certificate",
    )
    tls_group.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS verification (lab environments only)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="request timeout in seconds (default: 15)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        firewall_url = normalize_firewall_url(input("Firewall IP address or DNS name: "))
        username = input("Username: ").strip()
        if not username:
            raise ValueError("the username is empty")
        password = getpass.getpass("Password: ")
        if not password:
            raise ValueError("the password is empty")
        if args.timeout <= 0:
            raise ValueError("the timeout must be greater than zero")

        ssl_context = make_ssl_context(
            insecure=args.insecure,
            ca_bundle=str(args.ca_bundle) if args.ca_bundle else None,
        )
        key = generate_api_key(
            firewall_url,
            username,
            password,
            ssl_context=ssl_context,
            timeout=args.timeout,
        )
    except (ValueError, OSError, KeyGenerationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"\nAPI key generated: {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
