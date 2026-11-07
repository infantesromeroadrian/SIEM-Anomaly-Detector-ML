#!/usr/bin/env python3
"""Refresh the generated results block of README.md from results/*.json."""

import sys

from backend.eval.readme import main

if __name__ == "__main__":
    sys.exit(main())
