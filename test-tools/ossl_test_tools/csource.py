# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

"""Read and rewrite `static const ... kName[]` arrays in OpenSSL test .c files.

Two declaration shapes are recognised:

  PEM string arrays
      static const char *kName[] = {
          "-----BEGIN ...-----\\n",
          ...
          NULL
      };

  Hex byte arrays
      static const unsigned char kName[] = {
          0x30, 0x82, ...
      };

PEM arrays can be both read and rewritten in place.  Hex arrays are
read-only for now (they appear in tests like pkcs7test.c and
verify_extra_test.c as binary blobs that are hand-edited rarely).
"""

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CArrayBlock:
    name: str
    kind: str             # "pem" or "hex"
    decl_start: int       # offset of `static`
    decl_end: int         # offset just past `;`
    body_start: int       # offset just past `{`
    body_end: int         # offset of closing `}`


_DECL_RE = re.compile(
    r"static\s+const\s+(?:unsigned\s+)?char\s*"
    r"(?P<ptr>\*?)\s*"
    r"(?P<name>\w+)\s*\[\s*\]\s*=\s*\{"
)


def find_block(text, name):
    """Locate the declaration of `name` in `text`. Returns CArrayBlock or None."""
    for m in _DECL_RE.finditer(text):
        if m.group("name") != name:
            continue
        kind = "pem" if m.group("ptr") == "*" else "hex"
        body_start = m.end()
        close = _find_close(text, body_start)
        if close is None:
            return None
        body_end, decl_end = close
        return CArrayBlock(
            name=name, kind=kind,
            decl_start=m.start(), decl_end=decl_end,
            body_start=body_start, body_end=body_end,
        )
    return None


def _find_close(text, pos):
    """Walk forward from `pos` to find the matching `};`.

    Skips C string literals and comments so a stray `}` inside a quoted
    string can't confuse us.  Returns (body_end, decl_end) on success.
    """
    depth = 1
    n = len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            pos += 1
            while pos < n:
                if text[pos] == "\\":
                    pos += 2
                    continue
                if text[pos] == '"':
                    pos += 1
                    break
                pos += 1
            continue
        if c == "/" and pos + 1 < n:
            if text[pos + 1] == "*":
                end = text.find("*/", pos + 2)
                pos = (end + 2) if end >= 0 else n
                continue
            if text[pos + 1] == "/":
                end = text.find("\n", pos + 2)
                pos = (end + 1) if end >= 0 else n
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                body_end = pos
                pos += 1
                while pos < n and text[pos].isspace():
                    pos += 1
                if pos < n and text[pos] == ";":
                    return body_end, pos + 1
                return None
        pos += 1
    return None


_PEM_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")


def parse_pem(text, block):
    """Concatenate the C string literals inside `block` and unescape."""
    body = text[block.body_start:block.body_end]
    out = []
    for part in _PEM_STR_RE.findall(body):
        out.append(
            part.replace(r"\n", "\n")
                .replace(r"\t", "\t")
                .replace(r"\"", '"')
                .replace("\\\\", "\\")
        )
    return "".join(out)


def parse_hex(text, block):
    """Pull bytes from a `0xNN, 0xNN, ...` array body."""
    body = text[block.body_start:block.body_end]
    return bytes(int(b, 16) for b in _HEX_RE.findall(body))


def emit_pem(name, pem_text, type_name="char", indent="    "):
    """Render a PEM string array declaration in crltest.c style."""
    lines = [ln for ln in pem_text.splitlines() if ln.strip()]
    out = [f"static const {type_name} *{name}[] = {{"]
    for ln in lines:
        out.append(f'{indent}"{ln}\\n",')
    out.append(f"{indent}NULL")
    out.append("};")
    return "\n".join(out)


def replace_block(text, block, new_decl):
    return text[:block.decl_start] + new_decl + text[block.decl_end:]


def read_pem(path, name):
    """Return the PEM body of `name` in the .c file at `path`."""
    text = Path(path).read_text()
    block = find_block(text, name)
    if block is None:
        raise KeyError(f"variable {name!r} not found in {path}")
    if block.kind != "pem":
        raise ValueError(f"variable {name!r} in {path} is a hex array, not a PEM array")
    return parse_pem(text, block)


def read_der(path, name):
    """Return the raw bytes of `name` (a hex byte array) in `path`."""
    text = Path(path).read_text()
    block = find_block(text, name)
    if block is None:
        raise KeyError(f"variable {name!r} not found in {path}")
    if block.kind != "hex":
        raise ValueError(f"variable {name!r} in {path} is a PEM array, not a hex array")
    return parse_hex(text, block)


def update_pem(path, name, pem_text):
    """Replace the PEM block named `name` in `path` with `pem_text`.

    The variable must already exist in the file — this is an update,
    not an insertion.
    """
    path = Path(path)
    text = path.read_text()
    block = find_block(text, name)
    if block is None:
        raise KeyError(f"variable {name!r} not found in {path}")
    if block.kind != "pem":
        raise ValueError(f"variable {name!r} in {path} is not a PEM array")
    path.write_text(replace_block(text, block, emit_pem(name, pem_text)))


def has(path, name):
    """Cheap existence check; returns True iff `name` is declared in `path`."""
    return find_block(Path(path).read_text(), name) is not None
