#!/usr/bin/env python3
"""Compatibility entry-point for running the app from the workspace root."""

from mal_doc_scanner.app import app


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
