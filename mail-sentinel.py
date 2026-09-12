#!/usr/bin/env python3
"""Entry point. All logic lives in the sentinel package so it can be tested."""
import sys

from sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
