/* pkcs11dev_loader.h
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

/* Test harness interface to route wolfCrypt operations to a PKCS#11 module. */

#ifndef WC_PKCS11DEV_LOADER_H
#define WC_PKCS11DEV_LOADER_H

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_PKCS11DEV_ID 0x70313164 /* 'p' '1' '1' 'd' */

int  wc_Pkcs11Dev_Init(void);
void wc_Pkcs11Dev_Cleanup(void);
int  wc_Pkcs11Dev_FindCb(int currentId, int algoType);

#ifdef __cplusplus
}
#endif

#endif /* WC_PKCS11DEV_LOADER_H */
