# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Generator for the embedded artifacts in test/statem_clnt_construct_test.c.

Writes the client certificate/key (kClientCert, kClientKey) back into the C
source file, replacing the existing kXxx[] declarations.
"""

from pathlib import Path

from . import client_cert


def _cmd(args):
    client_cert.build(args.source)
    print(f"updated kClientCert kClientKey in {args.source}")


def register(subparsers):
    p = subparsers.add_parser(
        "statem_clnt_construct_test",
        help="Regenerate the client cert/key in test/statem_clnt_construct_test.c.",
    )
    p.add_argument("--source", type=Path, required=True,
                   help="Path to statem_clnt_construct_test.c")
    p.set_defaults(func=_cmd)
