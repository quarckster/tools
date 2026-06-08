# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Alt-trust-anchor artifacts for test_crl_indirect_wrong_ta.

  kRoot2                independent self-signed CA
  kIndirectCRLIssuerAlt same DN as kIndirectCRLIssuer, signed by kRoot2
  kCrlIndirectAlt       empty CRL signed by the alt issuer

The alt issuer's Subject DN matches the one named in kIndirectLeaf's CRLDP
crlIssuer field, so the CRL associates with the leaf via name lookup; but
because alt_issuer chains to kRoot2 (not kRoot), check_crl_chain rejects
on TA mismatch even after check_crl_path's inner X509_verify_cert succeeds.
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
    root2_key = cert_util.new_rsa_key()
    root2_name = cert_util.name(
        "US", "Nevada", "Reno",
        "Example Alt Corp", "Certificate Authority",
        "Example Alt Corp Root CA",
    )
    root2_skid = x509.SubjectKeyIdentifier.from_public_key(root2_key.public_key())
    root2 = (
        x509.CertificateBuilder()
        .subject_name(root2_name)
        .issuer_name(root2_name)
        .public_key(root2_key.public_key())
        .serial_number(1)
        .not_valid_before(CERT_NOT_BEFORE)
        .not_valid_after(CERT_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(root2_skid, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root2_skid),
            critical=False)
        .sign(private_key=root2_key, algorithm=hashes.SHA256())
    )

    alt_key = cert_util.new_rsa_key()
    alt_skid = x509.SubjectKeyIdentifier.from_public_key(alt_key.public_key())
    alt_issuer = (
        x509.CertificateBuilder()
        .subject_name(INDIRECT_ISSUER_DN)
        .issuer_name(root2_name)
        .public_key(alt_key.public_key())
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
        .add_extension(alt_skid, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root2_skid),
            critical=False)
        .sign(private_key=root2_key, algorithm=hashes.SHA256())
    )

    alt_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(INDIRECT_ISSUER_DN)
        .last_update(CRL_LAST_UPDATE)
        .next_update(CRL_NEXT_UPDATE)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(alt_skid),
            critical=False)
        .add_extension(
            x509.IssuingDistributionPoint(
                full_name=None, relative_name=None,
                only_contains_user_certs=False, only_contains_ca_certs=False,
                only_some_reasons=None, indirect_crl=True,
                only_contains_attribute_certs=False),
            critical=True)
        .add_extension(x509.CRLNumber(0x1000), critical=False)
        .sign(private_key=alt_key, algorithm=hashes.SHA256())
    )

    cert_util.update_cert_in_c(source_path, "kRoot2", root2)
    cert_util.update_cert_in_c(source_path, "kIndirectCRLIssuerAlt", alt_issuer)
    cert_util.update_crl_in_c(source_path, "kCrlIndirectAlt", alt_crl)


def _cmd(args):
    build(args.source)
    print(f"updated kRoot2 kIndirectCRLIssuerAlt kCrlIndirectAlt in {args.source}")


def register(sub):
    p = sub.add_parser(
        "alt-ta",
        help="Regenerate the alt-trust-anchor artifacts (kRoot2, alt issuer, alt CRL).",
    )
    p.add_argument("--source", type=Path, required=True, help="Path to crltest.c")
    p.set_defaults(func=_cmd)
