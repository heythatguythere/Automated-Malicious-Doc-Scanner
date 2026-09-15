#!/usr/bin/env python3
"""Compatibility entry-point for running the CLI from the workspace root."""

from mal_doc_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
