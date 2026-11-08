#!/usr/bin/env python3
# falcon_fx_tables.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1335, USA

"""Generate and validate the constants of the Falcon fixed-point signer
(WOLFSSL_FALCON_SIGN_FIXED in wolfcrypt/src/falcon.c).

A falcon_fx value is {lo, mi, hi} = hi (signed) + mi/2^32 + lo/2^64. Every
constant is rounded to the nearest multiple of its format's resolution.

falcon_fx_R[k] = 1/(2cos(phi)) for 1 <= k < 512, with 2^b <= k < 2^(b+1)
and phi = (4*brv_b(k - 2^b) + 1)*pi/2^(b+2), brv_b reversing b bits; this
is falcon_sm_R at fixed-point precision.

falcon_fx_cs[2i], [2i+1] = cos, sin of the falcon_gm_tab angle
pi*(2*brv_b(k - 2^b) + 1)/2^(b+1) of entry k = i + 2^floor(log2(i)), for
1 <= i < 512, as signed Q63 (value * 2^63, two's complement); entry 0 is
unused and zero. The signer only reads the lower half of each block
2^b <= k < 2^(b+1), which this index maps onto. The angle phi of
falcon_fx_R[k] is the one of falcon_gm_tab entry k + 2^b.

FALCON_FX_INV_Q109 is round(2^109/q) as a 96-bit integer in falcon_fx limbs.

sigma_min and 1/sigma are the exact values of the binary64 reference tables
falcon_fpr_sigma_min and fpr_inv_sigma, read from falcon.c.

The second half of each table is only needed for Falcon-1024 and is left
out when WOLFSSL_NO_FALCON_LEVEL5 is defined.

Run:
    python3 scripts/falcon_fx_tables.py            # print the C constants
    python3 scripts/falcon_fx_tables.py --check    # diff against falcon.c
"""

import argparse
import os
import re
import struct
import sys
from decimal import Decimal, getcontext
from fractions import Fraction

getcontext().prec = 90
PI = Decimal("3.14159265358979323846264338327950288419716939937510582097494"
             "459230781640628620899862803482534211706798214808651328230664")
LN2 = Decimal("0.693147180559945309417232121458176568075500134360255254120680"
              "009493393621969694715605863326996418687542001481021")
Q = 12289
SIGMA0 = Decimal("1.8205")
TAB_R = 512
TAB_CS = 512

FALCON_C = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "wolfcrypt", "src", "falcon.c")


def cos_sin(x):
    """Taylor series for cos and sin; |x| < 2*pi, so 90 digits is ample."""
    x2 = x * x
    c = Decimal(1)
    s = x
    tc = Decimal(1)
    ts = x
    k = 1
    eps = Decimal(10) ** -88
    while True:
        tc = -tc * x2 / ((2 * k - 1) * (2 * k))
        ts = -ts * x2 / ((2 * k) * (2 * k + 1))
        if abs(tc) < eps and abs(ts) < eps:
            return c, s
        c += tc
        s += ts
        k += 1


def rev(bits, j):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (j & 1)
        j >>= 1
    return r


def round_scaled(v, shift):
    """Nearest integer to v * 2^shift, ties away from zero."""
    x = Decimal(v) * (Decimal(2) ** shift)
    i = int(x.to_integral_value(rounding="ROUND_HALF_UP")) if x >= 0 else \
        -int((-x).to_integral_value(rounding="ROUND_HALF_UP"))
    return i


def fx_words(v):
    """(lo, mi, hi) of the 32.64 fixed-point value nearest to v."""
    i = round_scaled(v, 64)
    assert -(1 << 95) <= i < (1 << 95), "out of 32.64 range"
    i &= (1 << 96) - 1
    return (i & 0xFFFFFFFF, (i >> 32) & 0xFFFFFFFF, i >> 64)


def q63(v):
    i = round_scaled(v, 63)
    assert -(1 << 63) < i < (1 << 63), "out of Q63 range"
    return i & ((1 << 64) - 1)


def dbl(bits):
    return Fraction(struct.unpack("<d", struct.pack("<Q", bits))[0])


def r_table():
    out = [(0, 0, 0)]
    for k in range(1, TAB_R):
        b = k.bit_length() - 1
        phi = (4 * rev(b, k - (1 << b)) + 1) * PI / (Decimal(2) ** (b + 2))
        c, _ = cos_sin(phi)
        out.append(fx_words(1 / (2 * c)))
    return out


def cs_k(i):
    """falcon_gm_tab entry stored at half-table index i."""
    return i + (1 << (i.bit_length() - 1))


def cs_table():
    out = [0, 0]
    for i in range(1, TAB_CS):
        k = cs_k(i)
        b = k.bit_length() - 1
        ang = PI * (2 * rev(b, k - (1 << b)) + 1) / (Decimal(2) ** (b + 1))
        c, s = cos_sin(ang)
        out.append(q63(c))
        out.append(q63(s))
    return out


def parse_numbers(text, name):
    m = re.search(r"\b%s\[[^\]]*\]\s*=\s*\{(.*?)\};" % re.escape(name), text,
                  re.S)
    if m is None:
        return None
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    body = re.sub(r"^#.*$", "", body, flags=re.M)
    return [int(v.rstrip("ULul"), 0)
            for v in re.findall(r"0x[0-9A-Fa-f]+U?L*L?|\b\d+U?L*L?\b", body)]


def values_before_level5(text, name):
    """Number of values ahead of the WOLFSSL_NO_FALCON_LEVEL5 guard."""
    m = re.search(r"\b%s\[[^\]]*\]\s*=\s*\{(.*?)#ifndef "
                  r"WOLFSSL_NO_FALCON_LEVEL5" % re.escape(name), text, re.S)
    if m is None:
        return None
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    return len(re.findall(r"0x[0-9A-Fa-f]+U?L*L?|\b\d+U?L*L?\b", body))


def fpr_from_falcon_c(text, name):
    vals = parse_numbers(text, name)
    if vals is None:
        sys.exit("cannot find %s in falcon.c" % name)
    return [fx_words(Decimal(dbl(v).numerator) / Decimal(dbl(v).denominator))
            for v in vals]


def scalars(text):
    sm = fpr_from_falcon_c(text, "falcon_fpr_sigma_min")
    isg = fpr_from_falcon_c(text, "fpr_inv_sigma")
    assert len(sm) == 11 and len(isg) == 11
    return [
        ("falcon_fx_sigma_min", sm),
        ("falcon_fx_inv_sigma", isg),
    ], [
        ("FALCON_FX_SQRT2", fx_words(Decimal(2).sqrt())),
        ("FALCON_FX_LOG2", fx_words(LN2)),
        ("FALCON_FX_INV_LOG2", fx_words(1 / LN2)),
        ("FALCON_FX_INV_2SQRSIGMA0", fx_words(1 / (2 * SIGMA0 * SIGMA0))),
    ], round_scaled(Decimal(1) / Q, 109)


def fmt_fx(w):
    return "{ 0x%08XU, 0x%08XU, 0x%08XU }" % w


def emit(ctype, name, vals, per, fmt, split=True):
    out = ["static const %s %s[] = {" % (ctype, name)]
    half = len(vals) // 2 if split else len(vals)
    for lo, hi in ((0, half), (half, len(vals))):
        if lo == hi:
            continue
        if lo == half:
            out.append("#ifndef WOLFSSL_NO_FALCON_LEVEL5")
        for i in range(lo, hi, per):
            out.append("    " +
                       ", ".join(fmt(v) for v in vals[i:min(i + per, hi)]) +
                       ",")
    if split:
        out.append("#endif")
    out.append("};")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description="Print the Falcon fixed-point signer constants as C, or "
                    "check the ones in wolfcrypt/src/falcon.c.")
    parser.add_argument("--check", action="store_true",
                        help="compare against falcon.c instead of printing")
    check = parser.parse_args().check
    with open(FALCON_C, "r", encoding="utf-8") as fh:
        text = fh.read()

    R = r_table()
    CS = cs_table()
    small_tabs, defs, inv_q = scalars(text)

    # Spot checks: R[1] = sqrt(2)/2, cs[1] = (cos(pi/4), sin(pi/4)).
    assert R[1] == fx_words(Decimal(2).sqrt() / 2)
    assert CS[2] == CS[3] == q63(Decimal(2).sqrt() / 2)
    # The binary64 twiddles are within a few ulp of these.
    gm = parse_numbers(text, "falcon_gm_tab")
    if gm is not None:
        for i in range(2, 2 * TAB_CS):
            sv = CS[i] - (1 << 64) if CS[i] >> 63 else CS[i]
            g = dbl(gm[2 * cs_k(i >> 1) + (i & 1)])
            assert abs(Fraction(sv, 1 << 63) - g) < Fraction(1, 1 << 50)

    tables = [
        ("falcon_fx", "falcon_fx_R", R, 1, fmt_fx, True),
        ("word64", "falcon_fx_cs", CS, 2, lambda v: "0x%016XULL" % v, True),
    ]
    for name, vals in small_tabs:
        tables.append(("falcon_fx", name, vals, 1, fmt_fx, False))

    if not check:
        print("/* Generated by scripts/falcon_fx_tables.py - do not "
              "hand-edit */")
        for name, w in defs:
            print("#define %s { 0x%08XU, 0x%08XU, 0x%08XU }" % ((name,) + w))
        print("#define FALCON_FX_INV_Q109 { 0x%08XU, 0x%08XU, 0x%08XU }" %
              (inv_q & 0xFFFFFFFF, (inv_q >> 32) & 0xFFFFFFFF,
               inv_q >> 64))
        for ctype, name, vals, per, fmt, split in tables:
            print(emit(ctype, name, vals, per, fmt, split))
        return 0

    bad = 0
    for ctype, name, vals, per, fmt, split in tables:
        got = parse_numbers(text, name)
        flat = []
        for v in vals:
            flat.extend(v if isinstance(v, tuple) else [v])
        if got is None:
            print("FAIL %s: not found in falcon.c" % name)
            bad += 1
        elif got != flat:
            first = next((i for i in range(min(len(got), len(flat)))
                          if got[i] != flat[i]), min(len(got), len(flat)))
            print("FAIL %s: %d values in falcon.c, %d expected, first "
                  "difference at index %d" % (name, len(got), len(flat),
                                              first))
            bad += 1
        elif split and values_before_level5(text, name) != len(flat) // 2:
            print("FAIL %s: the WOLFSSL_NO_FALCON_LEVEL5 guard is not at the "
                  "half-way point" % name)
            bad += 1
        else:
            print("ok   %s (%d values)" % (name, len(flat)))
    for name, w in defs:
        m = re.search(r"#define %s \{ (0x[0-9A-F]+)U, (0x[0-9A-F]+)U, "
                      r"(0x[0-9A-F]+)U \}" % name, text)
        if m is None or tuple(int(x, 16) for x in m.groups()) != w:
            print("FAIL %s" % name)
            bad += 1
        else:
            print("ok   %s" % name)
    m = re.search(r"#define FALCON_FX_INV_Q109 \{ (0x[0-9A-F]+)U, "
                  r"(0x[0-9A-F]+)U, (0x[0-9A-F]+)U \}", text)
    if m is None or (int(m.group(1), 16) | (int(m.group(2), 16) << 32) |
                     (int(m.group(3), 16) << 64)) != inv_q:
        print("FAIL FALCON_FX_INV_Q109")
        bad += 1
    else:
        print("ok   FALCON_FX_INV_Q109")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
