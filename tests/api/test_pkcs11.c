/* test_pkcs11.c
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

#include <tests/unit.h>

#include <tests/api/api.h>
#include <tests/api/test_pkcs11.h>

#if defined(HAVE_PKCS11) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_VERIFY) && !defined(WC_NO_RNG) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>

static int         test_pkcs11_verify_init_calls = 0;
static int         test_pkcs11_verify_calls = 0;
static const byte* test_pkcs11_expected_sig = NULL;
static word32      test_pkcs11_expected_sig_len = 0;

static CK_RV test_pkcs11_get_mechanism_info(CK_SLOT_ID slotId,
    CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
    (void)slotId;

    if (type != CKM_ECDSA || info == NULL)
        return CKR_MECHANISM_INVALID;

    XMEMSET(info, 0, sizeof(*info));
    info->flags = CKF_VERIFY;
    return CKR_OK;
}

static CK_RV test_pkcs11_create_object(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR object)
{
    (void)session;
    (void)template;
    (void)count;

    if (object == NULL)
        return CKR_MECHANISM_INVALID;

    *object = 1;
    return CKR_OK;
}

static CK_RV test_pkcs11_destroy_object(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object)
{
    (void)session;
    (void)object;

    return CKR_OK;
}

static CK_RV test_pkcs11_verify_init(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;
    (void)key;

    test_pkcs11_verify_init_calls++;
    return CKR_OK;
}

static CK_RV test_pkcs11_verify(CK_SESSION_HANDLE session, CK_BYTE_PTR data,
    CK_ULONG dataLen, CK_BYTE_PTR signature, CK_ULONG signatureLen)
{
    (void)session;
    (void)data;
    (void)dataLen;

    test_pkcs11_verify_calls++;
    if (test_pkcs11_expected_sig == NULL ||
        signatureLen != test_pkcs11_expected_sig_len ||
        XMEMCMP(signature, test_pkcs11_expected_sig, signatureLen) != 0) {
        return CKR_SIGNATURE_INVALID;
    }

    return CKR_OK;
}

int test_wc_Pkcs11_EcdsaSigDecode(void)
{
    static const byte emptyR[] = {
        0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01
    };
    static const byte emptyS[] = {
        0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00
    };
    static const byte hash[] = { 0x00 };
    byte oversizedR[40];
    byte oversizedS[40];
    byte paddedSig[72];
    byte expectedSig[64];
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    wc_CryptoInfo info;
    ecc_key key;
    WC_RNG rng;
    int ret;
    int res = 0;
    int haveKey = 0;
    int haveRng = 0;
    EXPECT_DECLS;

    XMEMSET(&token, 0, sizeof(token));
    XMEMSET(&func, 0, sizeof(func));
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(oversizedR, 0, sizeof(oversizedR));
    oversizedR[0] = 0x30;
    oversizedR[1] = 0x26;
    oversizedR[2] = 0x02;
    oversizedR[3] = 0x21;
    oversizedR[4] = 0x01;
    oversizedR[37] = 0x02;
    oversizedR[38] = 0x01;
    oversizedR[39] = 0x01;
    XMEMSET(oversizedS, 0, sizeof(oversizedS));
    oversizedS[0] = 0x30;
    oversizedS[1] = 0x26;
    oversizedS[2] = 0x02;
    oversizedS[3] = 0x01;
    oversizedS[4] = 0x01;
    oversizedS[5] = 0x02;
    oversizedS[6] = 0x21;
    oversizedS[7] = 0x01;
    XMEMSET(paddedSig, 0, sizeof(paddedSig));
    paddedSig[0] = 0x30;
    paddedSig[1] = 0x46;
    paddedSig[2] = 0x02;
    paddedSig[3] = 0x21;
    paddedSig[5] = 0x80;
    paddedSig[37] = 0x02;
    paddedSig[38] = 0x21;
    paddedSig[40] = 0x81;
    XMEMSET(expectedSig, 0, sizeof(expectedSig));
    expectedSig[0] = 0x80;
    expectedSig[32] = 0x81;

    func.C_GetMechanismInfo = test_pkcs11_get_mechanism_info;
    func.C_CreateObject = test_pkcs11_create_object;
    func.C_DestroyObject = test_pkcs11_destroy_object;
    func.C_VerifyInit = test_pkcs11_verify_init;
    func.C_Verify = test_pkcs11_verify;
    token.func = &func;
    token.slotId = 1;
    token.handle = 1;
    token.version = WC_PCKS11VERSION_2_40;

    ret = wc_InitRng(&rng);
    ExpectIntEQ(ret, 0);
    if (ret == 0)
        haveRng = 1;
    if (ret == 0)
        ret = wc_ecc_init(&key);
    ExpectIntEQ(ret, 0);
    if (ret == 0)
        haveKey = 1;
    if (ret == 0)
        ret = wc_ecc_make_key(&rng, 32, &key);
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_ECDSA_VERIFY;
    info.pk.eccverify.hash = hash;
    info.pk.eccverify.hashlen = sizeof(hash);
    info.pk.eccverify.key = &key;
    info.pk.eccverify.res = &res;
    test_pkcs11_expected_sig = NULL;
    test_pkcs11_expected_sig_len = 0;

    if (ret == 0) {
        info.pk.eccverify.sig = emptyR;
        info.pk.eccverify.siglen = sizeof(emptyR);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = emptyS;
        info.pk.eccverify.siglen = sizeof(emptyS);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = oversizedR;
        info.pk.eccverify.siglen = sizeof(oversizedR);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = oversizedS;
        info.pk.eccverify.siglen = sizeof(oversizedS);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = paddedSig;
        info.pk.eccverify.siglen = sizeof(paddedSig);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        test_pkcs11_expected_sig = expectedSig;
        test_pkcs11_expected_sig_len = sizeof(expectedSig);
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
        ExpectIntEQ(res, 1);
        ExpectIntEQ(test_pkcs11_verify_init_calls, 1);
        ExpectIntEQ(test_pkcs11_verify_calls, 1);
    }

    test_pkcs11_expected_sig = NULL;
    test_pkcs11_expected_sig_len = 0;
    if (haveKey)
        wc_ecc_free(&key);
    if (haveRng)
        DoExpectIntEQ(wc_FreeRng(&rng), 0);

    return EXPECT_RESULT();
}

#define TEST_PKCS11_MAX_OBJS    8
#define TEST_PKCS11_MAX_ID_LEN  32
#define TEST_CKR_GENERAL_ERROR  ((CK_RV)0x00000005UL)

typedef struct TestPkcs11Obj {
    int             used;
    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE     keyType;
    CK_BBOOL        onToken;
    byte            id[TEST_PKCS11_MAX_ID_LEN];
    CK_ULONG        idLen;
    char            label[TEST_PKCS11_MAX_ID_LEN];
    CK_ULONG        labelLen;
} TestPkcs11Obj;

static TestPkcs11Obj test_pkcs11_objs[TEST_PKCS11_MAX_OBJS];
static TestPkcs11Obj test_pkcs11_find;
static CK_ULONG      test_pkcs11_find_mask;
static CK_ULONG      test_pkcs11_find_next;
static int           test_pkcs11_destroy_calls = 0;

#define TEST_PKCS11_FIND_CLASS  0x01
#define TEST_PKCS11_FIND_TYPE   0x02
#define TEST_PKCS11_FIND_TOKEN  0x04
#define TEST_PKCS11_FIND_ID     0x08
#define TEST_PKCS11_FIND_LABEL  0x10

static void test_pkcs11_reset(void)
{
    XMEMSET(test_pkcs11_objs, 0, sizeof(test_pkcs11_objs));
    test_pkcs11_destroy_calls = 0;
}

static TestPkcs11Obj* test_pkcs11_obj(CK_OBJECT_HANDLE h)
{
    if (h == 0 || h > TEST_PKCS11_MAX_OBJS || !test_pkcs11_objs[h - 1].used)
        return NULL;
    return &test_pkcs11_objs[h - 1];
}

static int test_pkcs11_count(CK_BBOOL onToken)
{
    int i;
    int cnt = 0;

    for (i = 0; i < TEST_PKCS11_MAX_OBJS; i++) {
        if (test_pkcs11_objs[i].used && test_pkcs11_objs[i].onToken == onToken)
            cnt++;
    }
    return cnt;
}

/* Applies the template to obj and returns a TEST_PKCS11_FIND_* mask. */
static CK_ULONG test_pkcs11_apply(TestPkcs11Obj* obj, CK_ATTRIBUTE_PTR tmpl,
    CK_ULONG cnt)
{
    CK_ULONG i;
    CK_ULONG mask = 0;

    for (i = 0; i < cnt; i++) {
        if (tmpl[i].type == CKA_CLASS) {
            obj->cls = *(CK_OBJECT_CLASS*)tmpl[i].pValue;
            mask |= TEST_PKCS11_FIND_CLASS;
        }
        else if (tmpl[i].type == CKA_KEY_TYPE) {
            obj->keyType = *(CK_KEY_TYPE*)tmpl[i].pValue;
            mask |= TEST_PKCS11_FIND_TYPE;
        }
        else if (tmpl[i].type == CKA_TOKEN) {
            obj->onToken = *(CK_BBOOL*)tmpl[i].pValue;
            mask |= TEST_PKCS11_FIND_TOKEN;
        }
        else if (tmpl[i].type == CKA_ID &&
                 tmpl[i].ulValueLen <= TEST_PKCS11_MAX_ID_LEN) {
            XMEMCPY(obj->id, tmpl[i].pValue, tmpl[i].ulValueLen);
            obj->idLen = tmpl[i].ulValueLen;
            mask |= TEST_PKCS11_FIND_ID;
        }
        else if (tmpl[i].type == CKA_LABEL &&
                 tmpl[i].ulValueLen <= TEST_PKCS11_MAX_ID_LEN) {
            XMEMCPY(obj->label, tmpl[i].pValue, tmpl[i].ulValueLen);
            obj->labelLen = tmpl[i].ulValueLen;
            mask |= TEST_PKCS11_FIND_LABEL;
        }
    }
    return mask;
}

static CK_RV test_pkcs11_store_create(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt, CK_OBJECT_HANDLE_PTR object)
{
    CK_ULONG i;

    (void)session;

    for (i = 0; i < TEST_PKCS11_MAX_OBJS; i++) {
        if (!test_pkcs11_objs[i].used)
            break;
    }
    if (i == TEST_PKCS11_MAX_OBJS)
        return TEST_CKR_GENERAL_ERROR;

    XMEMSET(&test_pkcs11_objs[i], 0, sizeof(test_pkcs11_objs[i]));
    test_pkcs11_objs[i].used = 1;
    (void)test_pkcs11_apply(&test_pkcs11_objs[i], tmpl, cnt);
    *object = i + 1;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_destroy(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object)
{
    TestPkcs11Obj* obj = test_pkcs11_obj(object);

    (void)session;

    test_pkcs11_destroy_calls++;
    if (obj == NULL)
        return TEST_CKR_GENERAL_ERROR;
    obj->used = 0;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_get_attr(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt)
{
    TestPkcs11Obj* obj = test_pkcs11_obj(object);
    CK_ULONG i;

    (void)session;

    if (obj == NULL)
        return TEST_CKR_GENERAL_ERROR;
    for (i = 0; i < cnt; i++) {
        if (tmpl[i].type != CKA_TOKEN || tmpl[i].pValue == NULL)
            return TEST_CKR_GENERAL_ERROR;
        *(CK_BBOOL*)tmpl[i].pValue = obj->onToken;
        tmpl[i].ulValueLen = sizeof(CK_BBOOL);
    }
    return CKR_OK;
}

static int test_pkcs11_matches(const TestPkcs11Obj* obj)
{
    const TestPkcs11Obj* f = &test_pkcs11_find;
    CK_ULONG m = test_pkcs11_find_mask;

    return obj->used &&
        (!(m & TEST_PKCS11_FIND_CLASS) || obj->cls == f->cls) &&
        (!(m & TEST_PKCS11_FIND_TYPE) || obj->keyType == f->keyType) &&
        (!(m & TEST_PKCS11_FIND_TOKEN) || obj->onToken == f->onToken) &&
        (!(m & TEST_PKCS11_FIND_ID) || (obj->idLen == f->idLen &&
            XMEMCMP(obj->id, f->id, f->idLen) == 0)) &&
        (!(m & TEST_PKCS11_FIND_LABEL) || (obj->labelLen == f->labelLen &&
            XMEMCMP(obj->label, f->label, f->labelLen) == 0));
}

static CK_RV test_pkcs11_store_find_init(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt)
{
    (void)session;

    XMEMSET(&test_pkcs11_find, 0, sizeof(test_pkcs11_find));
    test_pkcs11_find_mask = test_pkcs11_apply(&test_pkcs11_find, tmpl, cnt);
    test_pkcs11_find_next = 0;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_find(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE_PTR objects, CK_ULONG max, CK_ULONG_PTR cnt)
{
    (void)session;

    *cnt = 0;
    while (*cnt < max && test_pkcs11_find_next < TEST_PKCS11_MAX_OBJS) {
        if (test_pkcs11_matches(&test_pkcs11_objs[test_pkcs11_find_next]))
            objects[(*cnt)++] = test_pkcs11_find_next + 1;
        test_pkcs11_find_next++;
    }
    return CKR_OK;
}

static CK_RV test_pkcs11_store_find_final(CK_SESSION_HANDLE session)
{
    (void)session;

    return CKR_OK;
}

static CK_RV test_pkcs11_store_copy(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt,
    CK_OBJECT_HANDLE_PTR newObject)
{
    TestPkcs11Obj* obj = test_pkcs11_obj(object);
    CK_RV rv;

    if (obj == NULL)
        return TEST_CKR_GENERAL_ERROR;
    rv = test_pkcs11_store_create(session, NULL, 0, newObject);
    if (rv == CKR_OK) {
        test_pkcs11_objs[*newObject - 1] = *obj;
        (void)test_pkcs11_apply(&test_pkcs11_objs[*newObject - 1], tmpl, cnt);
    }
    return rv;
}

static CK_RV test_pkcs11_store_mech_info(CK_SLOT_ID slotId,
    CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
    (void)slotId;

    if (type != CKM_ECDSA || info == NULL)
        return CKR_MECHANISM_INVALID;

    XMEMSET(info, 0, sizeof(*info));
    info->flags = CKF_SIGN | CKF_VERIFY;
    return CKR_OK;
}

static void test_pkcs11_store_setup(Pkcs11Token* token, CK_FUNCTION_LIST* func)
{
    XMEMSET(token, 0, sizeof(*token));
    XMEMSET(func, 0, sizeof(*func));
    func->C_GetMechanismInfo = test_pkcs11_store_mech_info;
    func->C_CreateObject = test_pkcs11_store_create;
    func->C_CopyObject = test_pkcs11_store_copy;
    func->C_DestroyObject = test_pkcs11_store_destroy;
    func->C_GetAttributeValue = test_pkcs11_store_get_attr;
    func->C_FindObjectsInit = test_pkcs11_store_find_init;
    func->C_FindObjects = test_pkcs11_store_find;
    func->C_FindObjectsFinal = test_pkcs11_store_find_final;
    token->func = func;
    token->slotId = 1;
    token->handle = 1;
    token->version = WC_PCKS11VERSION_2_40;
    test_pkcs11_reset();
}

static int test_pkcs11_free_ecc(Pkcs11Token* token, ecc_key* key)
{
    wc_CryptoInfo info;

    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_FREE;
    info.free.algo = WC_ALGO_TYPE_PK;
    info.free.type = WC_PK_TYPE_EC_KEYGEN;
    info.free.obj = key;
    return wc_Pkcs11_CryptoDevCb(1, &info, token);
}

int test_wc_Pkcs11_FreeKeepsTokenKey(void)
{
    static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    static CK_BBOOL        isToken = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_TOKEN, &isToken,   sizeof(isToken)   }
    };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    CK_OBJECT_HANDLE sessObj = 0;
    CK_OBJECT_HANDLE tokObj = 0;
    ecc_key key;
    EXPECT_DECLS;

    test_pkcs11_store_setup(&token, &func);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(test_pkcs11_store_create(0, tmpl, 1, &sessObj), CKR_OK);
    ExpectIntEQ(test_pkcs11_store_create(0, tmpl, 2, &tokObj), CKR_OK);

    key.devCtx = (void*)(wc_ptr_t)tokObj;
    ExpectIntEQ(test_pkcs11_free_ecc(&token, &key), 0);
    ExpectNull(key.devCtx);
    ExpectNotNull(test_pkcs11_obj(tokObj));

    key.devCtx = (void*)(wc_ptr_t)(TEST_PKCS11_MAX_OBJS + 1);
    ExpectIntEQ(test_pkcs11_free_ecc(&token, &key), 0);
    ExpectNull(key.devCtx);

    key.devCtx = (void*)(wc_ptr_t)sessObj;
    ExpectIntEQ(test_pkcs11_free_ecc(&token, &key), 0);
    ExpectNull(key.devCtx);
    ExpectNull(test_pkcs11_obj(sessObj));
    ExpectIntEQ(test_pkcs11_destroy_calls, 1);
    ExpectIntEQ(test_pkcs11_count(CK_TRUE), 1);

    return EXPECT_RESULT();
}

static int test_pkcs11_make_ecc(ecc_key* key, WC_RNG* rng, const byte* id,
    int idLen)
{
    int ret = wc_ecc_init_id(key, (unsigned char*)id, idLen, NULL,
        INVALID_DEVID);
    if (ret == 0)
        ret = wc_ecc_make_key(rng, 32, key);
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
        ret = wc_AsyncWait(ret, &key->asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    return ret;
}

int test_wc_Pkcs11_StoreKeyPersistent(void)
{
    static const byte id[] = { 0x01, 0x02, 0x03, 0x04 };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    ecc_key key;
    WC_RNG rng;
    int i;
    EXPECT_DECLS;

    test_pkcs11_store_setup(&token, &func);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_pkcs11_make_ecc(&key, &rng, id, (int)sizeof(id)), 0);

    ExpectIntEQ(wc_Pkcs11StoreKey_ex(&token, PKCS11_KEY_TYPE_EC, 0, &key, 0),
        0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 2);
    ExpectIntEQ(test_pkcs11_count(CK_TRUE), 0);

    test_pkcs11_reset();
    ExpectIntEQ(wc_Pkcs11StoreKey_ex(&token, PKCS11_KEY_TYPE_EC, 0, &key, 1),
        0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
    ExpectIntEQ(test_pkcs11_count(CK_TRUE), 2);
    for (i = 0; i < TEST_PKCS11_MAX_OBJS; i++) {
        if (test_pkcs11_objs[i].used) {
            ExpectIntEQ(test_pkcs11_objs[i].idLen, sizeof(id));
            ExpectBufEQ(test_pkcs11_objs[i].id, id, sizeof(id));
        }
    }

    test_pkcs11_reset();
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &key), 0);
    ExpectIntEQ(test_pkcs11_count(CK_TRUE), 0);

    wc_ecc_free(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);

    return EXPECT_RESULT();
}

#endif
