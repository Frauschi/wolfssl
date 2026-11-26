/* pkcs11dev_loader.c
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

#include "pkcs11dev_loader.h"

#include <stdio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>

#ifndef WOLF_CRYPTO_CB_FIND
#error "pkcs11dev loader requires WOLF_CRYPTO_CB_FIND"
#endif

#define PKCS11DEV_MAX_SLOTS 16

static Pkcs11Dev   pkcs11dev_dev;
static Pkcs11Token pkcs11dev_token;
static int         pkcs11dev_refCount = 0;

static CK_UTF8CHAR pkcs11dev_soPin[]   = "wolfssl-test-so-pin";
static CK_UTF8CHAR pkcs11dev_userPin[] = "wolfssl-test-user-pin";

/* Re-initialize the first slot's token and set the user PIN on it. */
static int pkcs11dev_init_token(CK_SLOT_ID* slotId)
{
    CK_FUNCTION_LIST_PTR func = pkcs11dev_dev.func;
    CK_SLOT_ID slots[PKCS11DEV_MAX_SLOTS];
    CK_ULONG slotCnt = PKCS11DEV_MAX_SLOTS;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_UTF8CHAR label[32];
    CK_RV rv;

    rv = func->C_GetSlotList(CK_TRUE, slots, &slotCnt);
    if (rv == CKR_OK && slotCnt == 0) {
        fprintf(stderr, "pkcs11dev: no token present\n");
        return WC_HW_E;
    }
    if (rv == CKR_OK) {
        *slotId = slots[0];
        XMEMSET(label, ' ', sizeof(label));
        XMEMCPY(label, "wolfssl-test", 12);
        rv = func->C_InitToken(*slotId, pkcs11dev_soPin,
            (CK_ULONG)XSTRLEN((char*)pkcs11dev_soPin), label);
    }
    if (rv == CKR_OK) {
        rv = func->C_OpenSession(*slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &session);
    }
    if (rv == CKR_OK) {
        rv = func->C_Login(session, CKU_SO, pkcs11dev_soPin,
            (CK_ULONG)XSTRLEN((char*)pkcs11dev_soPin));
    }
    if (rv == CKR_OK) {
        rv = func->C_InitPIN(session, pkcs11dev_userPin,
            (CK_ULONG)XSTRLEN((char*)pkcs11dev_userPin));
        (void)func->C_Logout(session);
    }
    if (session != CK_INVALID_HANDLE)
        (void)func->C_CloseSession(session);

    if (rv != CKR_OK) {
        fprintf(stderr, "pkcs11dev: token setup failed: 0x%lx\n",
            (unsigned long)rv);
        return WC_HW_E;
    }
    return 0;
}

int wc_Pkcs11Dev_Init(void)
{
    int ret;
    const char* module;
    CK_SLOT_ID slotId = 0;

    if (pkcs11dev_refCount > 0) {
        /* Counted even on failure, as callers clean up regardless. */
        pkcs11dev_refCount++;
        /* A test may have emptied the device table with wolfCrypt_Cleanup(). */
        if (!wc_CryptoCb_IsDeviceRegistered(WC_PKCS11DEV_ID)) {
            ret = wc_CryptoCb_RegisterDevice(WC_PKCS11DEV_ID,
                wc_Pkcs11_CryptoDevCb, &pkcs11dev_token);
            if (ret != 0)
                return ret;
        }
        wc_CryptoCb_SetDeviceFindCb(wc_Pkcs11Dev_FindCb);
        return 0;
    }
    pkcs11dev_refCount = 1;

    module = XGETENV("WOLFSSL_PKCS11DEV_MODULE");
    if (module == NULL || *module == '\0') {
        fprintf(stderr, "pkcs11dev: set WOLFSSL_PKCS11DEV_MODULE\n");
        pkcs11dev_refCount = 0;
        return BAD_FUNC_ARG;
    }

    ret = wc_Pkcs11_Initialize(&pkcs11dev_dev, module, NULL);
    if (ret == 0) {
        ret = pkcs11dev_init_token(&slotId);
        if (ret == 0) {
            ret = wc_Pkcs11Token_Init(&pkcs11dev_token, &pkcs11dev_dev,
                (int)slotId, "wolfssl-test", pkcs11dev_userPin,
                (int)XSTRLEN((char*)pkcs11dev_userPin));
        }
        if (ret == 0) {
            ret = wc_CryptoCb_RegisterDevice(WC_PKCS11DEV_ID,
                wc_Pkcs11_CryptoDevCb, &pkcs11dev_token);
            if (ret != 0)
                wc_Pkcs11Token_Final(&pkcs11dev_token);
        }
        if (ret != 0)
            wc_Pkcs11_Finalize(&pkcs11dev_dev);
    }
    if (ret != 0) {
        pkcs11dev_refCount = 0;
        return ret;
    }

    wc_CryptoCb_SetDeviceFindCb(wc_Pkcs11Dev_FindCb);
    return 0;
}

void wc_Pkcs11Dev_Cleanup(void)
{
    if (pkcs11dev_refCount <= 0 || --pkcs11dev_refCount > 0)
        return;

    wc_CryptoCb_SetDeviceFindCb(NULL);
    wc_CryptoCb_UnRegisterDevice(WC_PKCS11DEV_ID);
    wc_Pkcs11Token_Final(&pkcs11dev_token);
    wc_Pkcs11_Finalize(&pkcs11dev_dev);
}

int wc_Pkcs11Dev_FindCb(int currentId, int algoType)
{
    (void)algoType;

    if (currentId == INVALID_DEVID)
        return WC_PKCS11DEV_ID;
    return currentId;
}
