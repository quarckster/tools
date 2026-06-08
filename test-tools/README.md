# ossl-test-tools

Python tools for OpenSSL's C tests. Edits test artifacts (certs, CRLs,
keys) into the .c source files in place by variable name.

## Setup

    cd test-tools
    uv sync

## Use

    uv run ossl-test-tools crltest all      --source path/to/crltest.c
    uv run ossl-test-tools crltest indirect --source path/to/crltest.c
    uv run ossl-test-tools crltest alt-ta   --source path/to/crltest.c
    uv run ossl-test-tools crltest no-chain --source path/to/crltest.c

Each subcommand has its own `--help`.

## Adding a new variable

Add an empty placeholder to the .c file:

    static const char *kSomething[] = {};

Then run the relevant subcommand. The placeholder gets populated.

## Adding a new generator

A subpackage of `ossl_test_tools` exposing `register(subparsers)`. Import
and register it from `cli.py`.

Two helpers worth knowing:

* `csource` — locate, read, and rewrite `static const ... kName[]`
  arrays. PEM string arrays and hex byte arrays are both supported for
  reading; only PEM is written.
* `cert_util` — cert/CRL/key builders plus `cert_from_c` /
  `update_cert_in_c` bridges.

Per-tool constants (DNs, validity windows, serials) stay in the tool's
own module.

## pem-to-c

Format a PEM file as a C declaration, for one-off pasting:

    uv run ossl-test-tools pem-to-c some.pem --name kSomething
