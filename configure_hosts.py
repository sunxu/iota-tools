#!/usr/bin/env python3
"""Explicit privileged hosts setup; no hidden global proxy or keychain mutation."""
import argparse
from tah_control.hosts import apply

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "remove"))
    print("hosts modified" if apply(parser.parse_args().action) else "hosts unchanged")
