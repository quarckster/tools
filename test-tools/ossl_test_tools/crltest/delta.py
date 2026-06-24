# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Delta-CRL artifacts for the X509_V_FLAG_USE_DELTAS path.

  kCrlDeltaBase    full CRL signed by kRoot, no revocations, carries a
                   Freshest CRL extension so EXFLAG_FRESHEST is set and
                   get_delta_sk() looks for a delta
  kCrlDeltaValid   delta CRL (deltaCRLIndicator -> base crlNumber) that
                   revokes kLeaf, valid time window around kVerify

Both CRLs are issued and signed by kRoot and share an identical
AuthorityKeyIdentifier (and no IDP), so check_delta_base() pairs the delta
with the base.  kRoot, kRootPrivateKey and kLeaf are read out of the source
file by name; no new certificates are generated.

The time window matches the indirect suite (CRL_LAST_UPDATE/CRL_NEXT_UPDATE)
so kVerify falls inside it: this exercises the happy path where the delta is
current.  The expired-delta regression case is intentionally not generated
here.
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .. import cert_util
from ._shared import CRL_LAST_UPDATE, CRL_NEXT_UPDATE, UTC

BASE_CRL_NUMBER = 0x1000
DELTA_CRL_NUMBER = 0x1001
REVOCATION_DATE = datetime.datetime(2026, 3, 20, 0, 0, 0, tzinfo=UTC)


def build(source_path):
    root_cert = cert_util.cert_from_c(source_path, "kRoot")
    root_key = cert_util.key_from_c(source_path, "kRootPrivateKey")
    leaf_cert = cert_util.cert_from_c(source_path, "kLeaf")
    akid = cert_util.akid_from_cert(root_cert)

    base_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(CRL_LAST_UPDATE)
        .next_update(CRL_NEXT_UPDATE)
        .add_extension(akid, critical=False)
        .add_extension(x509.CRLNumber(BASE_CRL_NUMBER), critical=False)
        .add_extension(
            x509.FreshestCRL([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "http://crl.example.com/delta.crl"
                    )],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]),
            critical=False)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf_cert.serial_number)
        .revocation_date(REVOCATION_DATE)
        .build()
    )
    delta_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(CRL_LAST_UPDATE)
        .next_update(CRL_NEXT_UPDATE)
        .add_revoked_certificate(revoked)
        .add_extension(akid, critical=False)
        .add_extension(x509.CRLNumber(DELTA_CRL_NUMBER), critical=False)
        .add_extension(x509.DeltaCRLIndicator(BASE_CRL_NUMBER), critical=True)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    cert_util.update_crl_in_c(source_path, "kCrlDeltaBase", base_crl)
    cert_util.update_crl_in_c(source_path, "kCrlDeltaValid", delta_crl)


def _cmd(args):
    build(args.source)
    print(f"updated kCrlDeltaBase kCrlDeltaValid in {args.source}")


def register(sub):
    p = sub.add_parser(
        "delta",
        help="Regenerate the delta-CRL artifacts (base + valid delta) for the "
             "USE_DELTAS path.",
    )
    p.add_argument("--source", type=Path, required=True, help="Path to crltest.c")
    p.set_defaults(func=_cmd)
