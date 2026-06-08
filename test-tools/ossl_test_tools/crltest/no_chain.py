# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""No-chain artifacts for test_crl_indirect_no_chain.

  kIndirectCRLIssuerNoChain  same DN as kIndirectCRLIssuer, signed by an
                             intermediate that we deliberately do not ship
  kCrlIndirectNoChain        empty CRL signed by nc_issuer, IDP indirectCRL=TRUE

The "missing" intermediate CA is generated in-memory and used only to sign
nc_issuer; its certificate never leaves the Python process.  At verification
time the inner CTX built by check_crl_path() cannot find nc_issuer's signer
in either the trust store or the untrusted stack, so X509_verify_cert
returns 0 and check_crl_path short-circuits before check_crl_chain runs.
"""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .. import cert_util
from ._shared import (
    CERT_NOT_AFTER, CERT_NOT_BEFORE, CRL_LAST_UPDATE, CRL_NEXT_UPDATE,
    INDIRECT_ISSUER_DN,
)


def build(source_path):
    missing_key = cert_util.new_rsa_key()
    missing_name = cert_util.name(
        "US", "Wyoming", "Cheyenne",
        "Example Phantom Corp", "Certificate Authority",
        "Example Phantom Missing Intermediate",
    )
    missing_skid = x509.SubjectKeyIdentifier.from_public_key(missing_key.public_key())

    nc_key = cert_util.new_rsa_key()
    nc_skid = x509.SubjectKeyIdentifier.from_public_key(nc_key.public_key())
    nc_issuer = (
        x509.CertificateBuilder()
        .subject_name(INDIRECT_ISSUER_DN)
        .issuer_name(missing_name)
        .public_key(nc_key.public_key())
        .serial_number(0x1000)
        .not_valid_before(CERT_NOT_BEFORE)
        .not_valid_after(CERT_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=True,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(nc_skid, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(missing_skid),
            critical=False)
        .sign(private_key=missing_key, algorithm=hashes.SHA256())
    )

    nc_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(INDIRECT_ISSUER_DN)
        .last_update(CRL_LAST_UPDATE)
        .next_update(CRL_NEXT_UPDATE)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(nc_skid),
            critical=False)
        .add_extension(
            x509.IssuingDistributionPoint(
                full_name=None, relative_name=None,
                only_contains_user_certs=False, only_contains_ca_certs=False,
                only_some_reasons=None, indirect_crl=True,
                only_contains_attribute_certs=False),
            critical=True)
        .add_extension(x509.CRLNumber(0x1000), critical=False)
        .sign(private_key=nc_key, algorithm=hashes.SHA256())
    )

    cert_util.update_cert_in_c(source_path, "kIndirectCRLIssuerNoChain", nc_issuer)
    cert_util.update_crl_in_c(source_path, "kCrlIndirectNoChain", nc_crl)


def _cmd(args):
    build(args.source)
    print(f"updated kIndirectCRLIssuerNoChain kCrlIndirectNoChain in {args.source}")


def register(sub):
    p = sub.add_parser(
        "no-chain",
        help="Regenerate the no-chain artifacts (nc_issuer + nc_crl).",
    )
    p.add_argument("--source", type=Path, required=True, help="Path to crltest.c")
    p.set_defaults(func=_cmd)
