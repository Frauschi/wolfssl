/* els_stub_descriptors.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* The four CLNS descriptor objects els_pkc_port.c references, as storage only.
 * Split out from els_stubs.c because CLNS declares them with types the public
 * headers leave incomplete, so a translation unit including those headers
 * cannot define them. Sound only while nothing dereferences them. */

#include <stdint.h>

#define STUB_DESC_SZ 256

#define STUB_DESCRIPTOR(name) \
    const uint64_t name[STUB_DESC_SZ / sizeof(uint64_t)] = { 0 }

STUB_DESCRIPTOR(mcuxClEcc_ECDSA_ProtocolDescriptor);
STUB_DESCRIPTOR(mcuxClRandomModes_mdCtrDrbg_AES256_DRG3);
STUB_DESCRIPTOR(mcuxClRsa_Mode_Sign_NoEncode);
STUB_DESCRIPTOR(mcuxClRsa_Mode_Verify_NoVerify);
