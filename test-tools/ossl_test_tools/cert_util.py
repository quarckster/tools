# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Generic cert/CRL/key helpers shared across test artifact generators.

Tool-specific constants (DNs, validity windows, serial assignments) stay
in each tool's own module.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import csource


def new_rsa_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def name(country, state, locality, org, ou, cn):
    """Build a six-attribute DN matching the layout used across OpenSSL tests."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def akid_from_cert(cert):
    """Build an AuthorityKeyIdentifier extension referencing `cert`'s SKID."""
    skid = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(skid)


def pem(obj):
    """Return the PEM encoding of a cert, CRL, or public key as text."""
    return obj.public_bytes(serialization.Encoding.PEM).decode()


def key_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def cert_from_c(path, name):
    """Load `name` from the .c file at `path` and parse it as an X.509 cert."""
    return x509.load_pem_x509_certificate(csource.read_pem(path, name).encode())


def key_from_c(path, name):
    return serialization.load_pem_private_key(
        csource.read_pem(path, name).encode(), password=None
    )


def crl_from_c(path, name):
    return x509.load_pem_x509_crl(csource.read_pem(path, name).encode())


def update_cert_in_c(path, name, cert):
    csource.update_pem(path, name, pem(cert))


def update_crl_in_c(path, name, crl):
    csource.update_pem(path, name, pem(crl))


def update_key_in_c(path, name, key):
    csource.update_pem(path, name, key_pem(key))
