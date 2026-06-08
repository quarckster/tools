# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Primary indirect-CRL artifacts.

  kIndirectCRLIssuer    cRLSign-only cert, signed by kRoot
  kIndirectLeaf         CRLDP names the indirect issuer by dirName
  kCrlIndirect          empty CRL, IDP indirectCRL=TRUE
  kCrlIndirectRevoked   leaf revoked, per-entry certificateIssuer = kRoot DN

kRoot and kRootPrivateKey are read out of the source file by name.
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from .. import cert_util
from ._shared import (
    CERT_NOT_AFTER, CERT_NOT_BEFORE, CRL_LAST_UPDATE, CRL_NEXT_UPDATE,
    INDIRECT_ISSUER_DN, INDIRECT_LEAF_DN, LEAF_NOT_AFTER, UTC,
)


def build(source_path):
    root_cert = cert_util.cert_from_c(source_path, "kRoot")
    root_key  = cert_util.key_from_c(source_path, "kRootPrivateKey")
    akid = cert_util.akid_from_cert(root_cert)

    icrl_key = cert_util.new_rsa_key()
    icrl_skid = x509.SubjectKeyIdentifier.from_public_key(icrl_key.public_key())
    icrl_cert = (
        x509.CertificateBuilder()
        .subject_name(INDIRECT_ISSUER_DN)
        .issuer_name(root_cert.subject)
        .public_key(icrl_key.public_key())
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
        .add_extension(icrl_skid, critical=False)
        .add_extension(akid, critical=False)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    leaf_key = cert_util.new_rsa_key()
    leaf_skid = x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(INDIRECT_LEAF_DN)
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x1001)
        .not_valid_before(CERT_NOT_BEFORE)
        .not_valid_after(LEAF_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False)
        .add_extension(leaf_skid, critical=False)
        .add_extension(akid, critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("indirect.example.com")]),
            critical=False)
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        "http://crl.example.com/indirect.crl"
                    )],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(INDIRECT_ISSUER_DN)],
                ),
            ]),
            critical=False)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    empty_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(INDIRECT_ISSUER_DN)
        .last_update(CRL_LAST_UPDATE)
        .next_update(CRL_NEXT_UPDATE)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(icrl_skid),
            critical=False)
        .add_extension(
            x509.IssuingDistributionPoint(
                full_name=None, relative_name=None,
                only_contains_user_certs=False, only_contains_ca_certs=False,
                only_some_reasons=None, indirect_crl=True,
                only_contains_attribute_certs=False),
            critical=True)
        .add_extension(x509.CRLNumber(0x1000), critical=False)
        .sign(private_key=icrl_key, algorithm=hashes.SHA256())
    )

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf_cert.serial_number)
        .revocation_date(datetime.datetime(2026, 3, 9, 12, 0, 0, tzinfo=UTC))
        .add_extension(
            x509.CertificateIssuer([x509.DirectoryName(root_cert.subject)]),
            critical=True)
        .build()
    )
    revoked_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(INDIRECT_ISSUER_DN)
        .last_update(CRL_LAST_UPDATE)
        .next_update(CRL_NEXT_UPDATE)
        .add_revoked_certificate(revoked)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(icrl_skid),
            critical=False)
        .add_extension(
            x509.IssuingDistributionPoint(
                full_name=None, relative_name=None,
                only_contains_user_certs=False, only_contains_ca_certs=False,
                only_some_reasons=None, indirect_crl=True,
                only_contains_attribute_certs=False),
            critical=True)
        .add_extension(x509.CRLNumber(0x1001), critical=False)
        .sign(private_key=icrl_key, algorithm=hashes.SHA256())
    )

    cert_util.update_cert_in_c(source_path, "kIndirectCRLIssuer", icrl_cert)
    cert_util.update_cert_in_c(source_path, "kIndirectLeaf", leaf_cert)
    cert_util.update_crl_in_c(source_path, "kCrlIndirect", empty_crl)
    cert_util.update_crl_in_c(source_path, "kCrlIndirectRevoked", revoked_crl)


def _cmd(args):
    build(args.source)
    print(f"updated kIndirectCRLIssuer kIndirectLeaf kCrlIndirect kCrlIndirectRevoked in {args.source}")


def register(sub):
    p = sub.add_parser(
        "indirect",
        help="Regenerate the primary indirect-CRL artifacts (issuer, leaf, empty + revoked CRLs).",
    )
    p.add_argument("--source", type=Path, required=True, help="Path to crltest.c")
    p.set_defaults(func=_cmd)
