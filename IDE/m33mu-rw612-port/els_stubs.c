/* els_stubs.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Every CLNS symbol els_pkc_port.c references, defined to fail.
 *
 * These are NOT a simulation of the EdgeLock hardware and they compute
 * nothing. They exist so this firmware can link the port and then assert the
 * property that matters when the hardware is missing: wolfCrypt still returns
 * correct answers, in software, with the port registered.
 *
 * m33mu emulates an ELS whose register interface was invented for its own test
 * firmware, so the real CLNS library cannot run on it. Until that changes,
 * running the actual offload stays a hardware job.
 *
 * The key reference codec and the AES key wrap container that main.c also
 * exercises are pure software and would link without any of this; they are
 * only here because they share a translation unit with the offload arms.
 *
 * Each stub keeps the vendor's flow protection bookkeeping (ENTRY/EXIT) so the
 * port's token check passes and it takes its ordinary status-driven error
 * path, rather than the token-mismatch path a naive stub would trigger.
 */

#include <mcuxClEls.h>
#include <mcuxClEcc.h>
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#include <mcuxClRsa.h>
#include <mcuxClSession.h>
#include <mcuxCsslFlowProtection.h>

/* status_t and ELS_Type, for the bring-up stub at the end of this file */
#include <mcux_els.h>

/* ---------------------------------------------------------------------------
 * ELS
 * ------------------------------------------------------------------------ */

#define ELS_STUB_EXIT(name) \
    MCUX_CSSL_FP_FUNCTION_EXIT(name, MCUXCLELS_STATUS_SW_FAULT)

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Hash_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Hash_Async(
    mcuxClEls_HashOption_t options, uint8_t const* pInput, size_t inputLength,
    uint8_t* pDigest)
{
    (void)options; (void)pInput; (void)inputLength; (void)pDigest;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Hash_Async);
    ELS_STUB_EXIT(mcuxClEls_Hash_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Cipher_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Cipher_Async(
    mcuxClEls_CipherOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pKey, size_t keyLength, uint8_t const* pInput,
    size_t inputLength, uint8_t* pIV, uint8_t* pOutput)
{
    (void)options; (void)keyIdx; (void)pKey; (void)keyLength;
    (void)pInput; (void)inputLength; (void)pIV; (void)pOutput;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Cipher_Async);
    ELS_STUB_EXIT(mcuxClEls_Cipher_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Cmac_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Cmac_Async(
    mcuxClEls_CmacOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pKey, size_t keyLength, uint8_t const* pInput,
    size_t inputLength, uint8_t* pMac)
{
    (void)options; (void)keyIdx; (void)pKey; (void)keyLength;
    (void)pInput; (void)inputLength; (void)pMac;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Cmac_Async);
    ELS_STUB_EXIT(mcuxClEls_Cmac_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Aead_Init_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Aead_Init_Async(
    mcuxClEls_AeadOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pKey, size_t keyLength, uint8_t const* pIV,
    size_t ivLength, uint8_t* pAeadCtx)
{
    (void)options; (void)keyIdx; (void)pKey; (void)keyLength;
    (void)pIV; (void)ivLength; (void)pAeadCtx;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Aead_Init_Async);
    ELS_STUB_EXIT(mcuxClEls_Aead_Init_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Aead_UpdateAad_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Aead_UpdateAad_Async(
    mcuxClEls_AeadOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pKey, size_t keyLength, uint8_t const* pAad,
    size_t aadLength, uint8_t* pAeadCtx)
{
    (void)options; (void)keyIdx; (void)pKey; (void)keyLength;
    (void)pAad; (void)aadLength; (void)pAeadCtx;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Aead_UpdateAad_Async);
    ELS_STUB_EXIT(mcuxClEls_Aead_UpdateAad_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Aead_UpdateData_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Aead_UpdateData_Async(
    mcuxClEls_AeadOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pKey, size_t keyLength, uint8_t const* pInput,
    size_t inputLength, uint8_t* pOutput, uint8_t* pAeadCtx)
{
    (void)options; (void)keyIdx; (void)pKey; (void)keyLength;
    (void)pInput; (void)inputLength; (void)pOutput; (void)pAeadCtx;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Aead_UpdateData_Async);
    ELS_STUB_EXIT(mcuxClEls_Aead_UpdateData_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Aead_Finalize_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Aead_Finalize_Async(
    mcuxClEls_AeadOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pKey, size_t keyLength, size_t aadLength,
    size_t dataLength, uint8_t* pTag, uint8_t* pAeadCtx)
{
    (void)options; (void)keyIdx; (void)pKey; (void)keyLength;
    (void)aadLength; (void)dataLength; (void)pTag; (void)pAeadCtx;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Aead_Finalize_Async);
    ELS_STUB_EXIT(mcuxClEls_Aead_Finalize_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Rng_DrbgRequest_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Rng_DrbgRequest_Async(
    uint8_t* pOutput, size_t outputLength)
{
    (void)pOutput; (void)outputLength;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Rng_DrbgRequest_Async);
    ELS_STUB_EXIT(mcuxClEls_Rng_DrbgRequest_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_WaitForOperation)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_WaitForOperation(
    mcuxClEls_ErrorHandling_t errorHandling)
{
    (void)errorHandling;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_WaitForOperation);
    ELS_STUB_EXIT(mcuxClEls_WaitForOperation);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_GetKeyProperties)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_GetKeyProperties(
    mcuxClEls_KeyIndex_t keyIdx, mcuxClEls_KeyProp_t* pKeyProp)
{
    (void)keyIdx; (void)pKeyProp;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_GetKeyProperties);
    ELS_STUB_EXIT(mcuxClEls_GetKeyProperties);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_KeyDelete_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_KeyDelete_Async(
    mcuxClEls_KeyIndex_t keyIdx)
{
    (void)keyIdx;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_KeyDelete_Async);
    ELS_STUB_EXIT(mcuxClEls_KeyDelete_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_KeyImport_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_KeyImport_Async(
    mcuxClEls_KeyImportOption_t options, uint8_t const* pImportKey,
    size_t importKeyLength, mcuxClEls_KeyIndex_t wrappingKeyIdx,
    mcuxClEls_KeyIndex_t targetKeyIdx)
{
    (void)options; (void)pImportKey; (void)importKeyLength;
    (void)wrappingKeyIdx; (void)targetKeyIdx;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_KeyImport_Async);
    ELS_STUB_EXIT(mcuxClEls_KeyImport_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_KeyExport_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_KeyExport_Async(
    mcuxClEls_KeyIndex_t wrappingKeyIdx, mcuxClEls_KeyIndex_t exportKeyIdx,
    uint8_t* pOutput)
{
    (void)wrappingKeyIdx; (void)exportKeyIdx; (void)pOutput;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_KeyExport_Async);
    ELS_STUB_EXIT(mcuxClEls_KeyExport_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_Ckdf_Sp800108_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_Ckdf_Sp800108_Async(
    mcuxClEls_KeyIndex_t derivationKeyIdx, mcuxClEls_KeyIndex_t targetKeyIdx,
    mcuxClEls_KeyProp_t targetKeyProperties, uint8_t const* pDerivationData)
{
    (void)derivationKeyIdx; (void)targetKeyIdx;
    (void)targetKeyProperties; (void)pDerivationData;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_Ckdf_Sp800108_Async);
    ELS_STUB_EXIT(mcuxClEls_Ckdf_Sp800108_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_EccKeyGen_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_EccKeyGen_Async(
    mcuxClEls_EccKeyGenOption_t options, mcuxClEls_KeyIndex_t signingKeyIdx,
    mcuxClEls_KeyIndex_t privateKeyIdx, mcuxClEls_KeyProp_t generatedKeyProperties,
    uint8_t const* pRandomData, uint8_t* pPublicKey)
{
    (void)options; (void)signingKeyIdx; (void)privateKeyIdx;
    (void)generatedKeyProperties; (void)pRandomData; (void)pPublicKey;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_EccKeyGen_Async);
    ELS_STUB_EXIT(mcuxClEls_EccKeyGen_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_EccSign_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_EccSign_Async(
    mcuxClEls_EccSignOption_t options, mcuxClEls_KeyIndex_t keyIdx,
    uint8_t const* pInputHash, uint8_t const* pInputMessage,
    size_t inputMessageLength, uint8_t* pOutput)
{
    (void)options; (void)keyIdx; (void)pInputHash;
    (void)pInputMessage; (void)inputMessageLength; (void)pOutput;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_EccSign_Async);
    ELS_STUB_EXIT(mcuxClEls_EccSign_Async);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEls_EccVerify_Async)
MCUXCLELS_API MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEls_Status_t) mcuxClEls_EccVerify_Async(
    mcuxClEls_EccVerifyOption_t options, uint8_t const* pInputHash,
    uint8_t const* pInputMessage, size_t inputMessageLength,
    uint8_t const* pSignatureAndPubKey, uint8_t* pOutput)
{
    (void)options; (void)pInputHash; (void)pInputMessage;
    (void)inputMessageLength; (void)pSignatureAndPubKey; (void)pOutput;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEls_EccVerify_Async);
    ELS_STUB_EXIT(mcuxClEls_EccVerify_Async);
}

/* ---------------------------------------------------------------------------
 * PKC tier: ECC, RSA, session and RNG plumbing
 * ------------------------------------------------------------------------ */

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_Sign)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_Sign(
    mcuxClSession_Handle_t pSession, const mcuxClEcc_Sign_Param_t* pParam)
{
    (void)pSession; (void)pParam;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_Sign);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_Sign, MCUXCLECC_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_Verify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_Verify(
    mcuxClSession_Handle_t pSession, const mcuxClEcc_Verify_Param_t* pParam)
{
    (void)pSession; (void)pParam;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_Verify);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_Verify, MCUXCLECC_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClEcc_PointMult)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClEcc_Status_t) mcuxClEcc_PointMult(
    mcuxClSession_Handle_t pSession, const mcuxClEcc_PointMult_Param_t* pParam)
{
    (void)pSession; (void)pParam;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClEcc_PointMult);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClEcc_PointMult, MCUXCLECC_STATUS_FAULT_ATTACK);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_sign)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_sign(
    mcuxClSession_Handle_t pSession, const mcuxClRsa_Key* const pKey,
    mcuxCl_InputBuffer_t pMessageOrDigest, const uint32_t messageLength,
    const mcuxClRsa_SignVerifyMode pPaddingMode, const uint32_t saltLength,
    const uint32_t options, mcuxCl_Buffer_t pSignature)
{
    (void)pSession; (void)pKey; (void)pMessageOrDigest; (void)messageLength;
    (void)pPaddingMode; (void)saltLength; (void)options; (void)pSignature;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_sign);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_sign, MCUXCLRSA_STATUS_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRsa_verify)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRsa_Status_t) mcuxClRsa_verify(
    mcuxClSession_Handle_t pSession, const mcuxClRsa_Key* const pKey,
    mcuxCl_InputBuffer_t pMessageOrDigest, const uint32_t messageLength,
    mcuxCl_Buffer_t pSignature, const mcuxClRsa_SignVerifyMode pVerifyMode,
    const uint32_t saltLength, const uint32_t options, mcuxCl_Buffer_t pOutput)
{
    (void)pSession; (void)pKey; (void)pMessageOrDigest; (void)messageLength;
    (void)pSignature; (void)pVerifyMode; (void)saltLength; (void)options;
    (void)pOutput;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRsa_verify);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRsa_verify, MCUXCLRSA_STATUS_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClSession_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClSession_Status_t) mcuxClSession_init(
    mcuxClSession_Handle_t pSession, uint32_t* const pCpuWaBuffer,
    uint32_t cpuWaLength, uint32_t* const pPkcWaBuffer, uint32_t pkcWaLength)
{
    (void)pSession; (void)pCpuWaBuffer; (void)cpuWaLength;
    (void)pPkcWaBuffer; (void)pkcWaLength;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClSession_init);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClSession_init, MCUXCLSESSION_STATUS_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_init)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_init(
    mcuxClSession_Handle_t pSession, mcuxClRandom_Context_t pContext,
    mcuxClRandom_Mode_t mode)
{
    (void)pSession; (void)pContext; (void)mode;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_init);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_init, MCUXCLRANDOM_STATUS_ERROR);
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClRandom_ncInit)
MCUX_CSSL_FP_PROTECTED_TYPE(mcuxClRandom_Status_t) mcuxClRandom_ncInit(
    mcuxClSession_Handle_t pSession)
{
    (void)pSession;
    MCUX_CSSL_FP_FUNCTION_ENTRY(mcuxClRandom_ncInit);
    MCUX_CSSL_FP_FUNCTION_EXIT(mcuxClRandom_ncInit, MCUXCLRANDOM_STATUS_ERROR);
}

/* ---------------------------------------------------------------------------
 * Platform bring-up
 * ------------------------------------------------------------------------ */

/* This one succeeds, and that is the point.
 *
 * wc_ElsPkc_Init() brings the peripheral up before it registers the crypto
 * callback, and returns early if the bring-up fails. Failing here would leave
 * nothing registered and the fallback test would have no port to fall back
 * from. Reporting success instead lets the port register and dispatch
 * normally, so every operation reaches an ELS stub above and fails there -
 * which is the path under test.
 */
status_t ELS_PowerDownWakeupInit(ELS_Type* base)
{
    (void)base;
    return kStatus_Success;
}
