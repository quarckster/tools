# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Dump PEM files as C string arrays.

Useful for the first-time insertion of a new variable into a .c file;
subsequent updates should go through the `csource` module so the file is
edited in place rather than copy-pasted from stdout.
"""

import sys
from pathlib import Path

from . import csource


def _cmd(args):
    out = sys.stdout
    for path in args.files:
        text = Path(path).read_text()
        name = args.name if args.name and len(args.files) == 1 else Path(path).stem
        out.write(csource.emit_pem(name, text))
        out.write("\n\n")


def register(subparsers):
    p = subparsers.add_parser(
        "pem-to-c",
        help="Format PEM file(s) as `static const char *kName[]` arrays.",
    )
    p.add_argument("files", nargs="+", type=Path, help="PEM files to format")
    p.add_argument("--name", help="Variable name (single-file form only)")
    p.set_defaults(func=_cmd)
