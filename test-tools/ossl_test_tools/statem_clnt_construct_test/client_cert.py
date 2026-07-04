# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Client certificate + key for statem_clnt_construct_test.c.

  kClientCert  self-signed RSA leaf with digitalSignature key usage
  kClientKey   its private key

The certificate is only ever serialized by the client-side construct
functions under test; it is never validated, so a self-signed leaf with a
long validity window is enough.  The key is signing-capable so the same
material can also drive a CertificateVerify test.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .. import cert_util

NOT_BEFORE = datetime.datetime(2026, 1, 1)
NOT_AFTER = datetime.datetime(2046, 1, 1)


def build(source_path):
    key = cert_util.new_rsa_key()
    subject = cert_util.name(
        "US", "Wyoming", "Cheyenne",
        "OpenSSL Test", "statem_clnt", "statem_clnt test client",
    )
    skid = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x100)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(skid, critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_util.update_cert_in_c(source_path, "kClientCert", cert)
    cert_util.update_key_in_c(source_path, "kClientKey", key)
