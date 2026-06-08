# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Constants for the indirect-CRL artifact suite.

These values are baked into crltest.c's expectations (verification time
windows, DN matching by the CRLDP-by-name lookup): changing one here
without updating crltest.c will silently break the tests.
"""

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

UTC = datetime.timezone.utc

CERT_NOT_BEFORE = datetime.datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC)
CERT_NOT_AFTER  = datetime.datetime(2036, 3, 7, 12, 0, 0, tzinfo=UTC)
LEAF_NOT_AFTER  = datetime.datetime(2027, 3, 10, 12, 0, 0, tzinfo=UTC)

CRL_LAST_UPDATE = datetime.datetime(2026, 3, 10, 8, 0, 0, tzinfo=UTC)
CRL_NEXT_UPDATE = datetime.datetime(2026, 6, 8, 8, 0, 0, tzinfo=UTC)

# The DN used by the legitimate indirect CRL issuer AND by every imposter
# (alt-TA, no-chain).  The shared DN is what makes CRLDP-by-name lookup
# from kIndirectLeaf land on each imposter during verification.
INDIRECT_ISSUER_DN = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME,            "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "Example Corp"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME,              "Example Corp Indirect CRL Issuer"),
])

INDIRECT_LEAF_DN = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "California"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "Example Corp"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Web Services"),
    x509.NameAttribute(NameOID.COMMON_NAME,              "indirect.example.com"),
])
