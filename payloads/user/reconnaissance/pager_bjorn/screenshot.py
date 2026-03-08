#!/usr/bin/env python3
"""Capture the current framebuffer to a PNG file.

Usage: python3 screenshot.py [output_path] [rotation]
  output_path: defaults to /tmp/screenshot.png
  rotation: 0=portrait, 270=landscape (default: 270)

Reads /dev/fb0 directly — captures whatever is currently displayed.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pagerctl import Pager

def main():
    output = sys.argv[1] if len(sys.argv) > 1 else '/tmp/screenshot.png'
    rotation = int(sys.argv[2]) if len(sys.argv) > 2 else 270

    p = Pager()
    p.init()
    ret = p.screenshot(output, rotation)
    p.cleanup()

    if ret == 0:
        print(f"Screenshot saved to {output}")
    else:
        print(f"Screenshot failed (return code {ret})", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
