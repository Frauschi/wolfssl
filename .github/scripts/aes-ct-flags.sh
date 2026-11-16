#!/bin/sh
#
# Check the WC_AES_BLOCK_CT and WC_AES_GHASH_CT that aes.h derives for each
# configuration, and that aes.c's #error guards accept them.
#
# Usage: .github/scripts/aes-ct-flags.sh   (CC overrides the compiler)

set -u

root="$(cd "$(dirname "$0")/../.." && pwd)"
cc="${CC:-cc}"
fails=0

# An empty user_settings.h keeps the host's options.h out of the build, and
# empty platform headers let the offload cases preprocess on any host.
cfg="$(mktemp -d)"
trap 'rm -rf "${cfg}"' EXIT
# glibc wants gnu/stubs-32.h once the host's __x86_64__ is undefined.
mkdir -p "${cfg}/linux" "${cfg}/gnu" "${cfg}/crypto" "${cfg}/calib"
for h in user_settings.h linux/if_alg.h linux/socket.h kcapi.h \
         crypto/cryptodev.h fsl_mmcau.h fsl_dcp.h cryptoauthlib.h \
         wmmintrin.h emmintrin.h smmintrin.h \
         calib/calib_command.h calib/calib_aes_gcm.h gnu/stubs-32.h \
         gnu/stubs-x32.h; do
    : > "${cfg}/${h}"
done

# The host architecture is undefined so each case states its own.
host="-U__x86_64__ -U__i386__ -U__aarch64__ -U__arm__ -U__riscv"
host="${host} -U__powerpc64__ -U__powerpc__ -U__ARM_ARCH -U__ARM_ARCH_PROFILE"
host="${host} -U__riscv_zkt -U__riscv_zvkt"
inc=""

# pp <probe> [-DFLAG ...]: preprocess aes.h followed by the probe lines
pp() {
    probe="$1"
    shift
    # shellcheck disable=SC2086
    printf '%s\n%s\n' '#include <wolfssl/wolfcrypt/aes.h>' "${probe}" | \
        "${cc}" -E -P -x c -I"${cfg}" ${inc} -I"${root}" \
            -DWOLFSSL_USER_SETTINGS ${host} "$@" - 2>&1
}

# check <block yes|no> <ghash yes|no> [-DFLAG ...]
check() {
    want_block="$1"
    want_ghash="$2"
    shift 2
    out="$(pp "$(printf '%s\n' '#ifdef WC_AES_BLOCK_CT' 'block=yes' '#endif' \
            '#ifdef WC_AES_GHASH_CT' 'ghash=yes' '#endif')" "$@")"
    rc=$?
    case "${out}" in *block=yes*) block=yes ;; *) block=no ;; esac
    case "${out}" in *ghash=yes*) ghash=yes ;; *) ghash=no ;; esac
    # aes.c's guards reject a flag set over code that is not constant time;
    # a second pass adds the other AES modes where settings.h allows them.
    passes="base modes"
    extra_gcm=""
    for arg in "$@"; do
        case "${arg}" in
            -DNO_AES|-DWOLF_CRYPTO_CB_ONLY_AES) passes="base" ;;
            -DHAVE_AESGCM) extra_gcm="${gcm_modes}" ;;
        esac
    done
    for pass in ${passes}; do
        extra=""
        [ "${pass}" = modes ] && extra="${modes} ${extra_gcm}"
        # shellcheck disable=SC2086
        src="$("${cc}" -E -P -x c -I"${cfg}" -I"${root}" \
                -DWOLFSSL_USER_SETTINGS ${host} "$@" ${extra} \
                "${root}/wolfcrypt/src/aes.c" 2>&1 >/dev/null)" || {
            rc=2
            out="${src}"
        }
    done
    if [ "${rc}" -eq 0 ] && [ "${block}" = "${want_block}" ] && \
       [ "${ghash}" = "${want_ghash}" ]; then
        echo "ok    block=${block} ghash=${ghash}  $*"
    else
        echo "FAIL  block=${block} ghash=${ghash} (want ${want_block}" \
             "${want_ghash}, rc ${rc})  $*"
        [ "${rc}" -ne 0 ] && echo "${out}" | grep -m3 -E 'error:|aes.h set'
        fails=$((fails + 1))
    fi
}

# check_engine [-DFLAG ...]: an AES engine whose headers come from a vendor
# SDK; each missing header is stubbed and aes.h must leave both flags unset.
check_engine() {
    sdk="${cfg}/sdk"
    rm -rf "${sdk}"
    mkdir -p "${sdk}"
    tries=0
    inc="-I${sdk}"
    while :; do
        out="$(pp "$(printf '%s\n' \
                '#if defined(WC_AES_BLOCK_CT) || defined(WC_AES_GHASH_CT)' \
                'claimed' '#endif')" "$@")"
        rc=$?
        hdr="$(printf '%s\n' "${out}" | sed -n \
            -e "s/.*fatal error: '\([^']*\)' file not found.*/\1/p" \
            -e 's/.*fatal error: \([^:]*\): No such file or directory.*/\1/p' |
            head -1)"
        [ "${rc}" -ne 0 ] && [ -n "${hdr}" ] && [ "${tries}" -lt 30 ] || break
        mkdir -p "$(dirname "${sdk}/${hdr}")"
        : > "${sdk}/${hdr}"
        tries=$((tries + 1))
    done
    inc=""
    case "${out}" in
        *claimed*) echo "FAIL  claimed  $*"; fails=$((fails + 1)) ;;
        *) if [ "${rc}" -eq 0 ]; then
               echo "ok    unknown  $*"
           else
               echo "FAIL  rc ${rc}  $*"
               printf '%s\n' "${out}" | grep -m3 'error'
               fails=$((fails + 1))
           fi ;;
    esac
}

# check_touch <yes|no> [-DFLAG ...]: is WOLFSSL_AES_TOUCH_LINES defined
check_touch() {
    want="$1"
    shift
    out="$(pp "$(printf '%s\n' '#ifdef WOLFSSL_AES_TOUCH_LINES' 'touch=yes' \
            '#endif')" "$@")"
    rc=$?
    case "${out}" in *touch=yes*) touch=yes ;; *) touch=no ;; esac
    if [ "${rc}" -eq 0 ] && [ "${touch}" = "${want}" ]; then
        echo "ok    touch=${touch}  $*"
    else
        echo "FAIL  touch=${touch} (want ${want}, rc ${rc})  $*"
        fails=$((fails + 1))
    fi
}

# check_im <variant> [-DFLAG ...]: the GCM_INT_MUL multiply variant aes.h picks
check_im() {
    want="$1"
    shift
    out="$(pp "$(printf '%s\n' '#if defined(GCM_IM_64)' 'im=64' \
            '#elif defined(GCM_IM_32W)' 'im=32W' '#elif defined(GCM_IM_32)' \
            'im=32' '#endif')" "$@")"
    im="$(printf '%s\n' "${out}" | sed -n 's/^im=//p')"
    if [ "${im}" = "${want}" ]; then
        echo "ok    im=${im}  $*"
    else
        echo "FAIL  im=${im} (want ${want})  $*"
        fails=$((fails + 1))
    fi
}

# check_error <fragment of the expected #error> [-DFLAG ...]
check_error() {
    want="$1"
    shift
    out="$(pp "" "$@")"
    case "${out}" in
        *"${want}"*) echo "ok    refused  $*" ;;
        *) echo "FAIL  not refused  $*"; fails=$((fails + 1)) ;;
    esac
}

modes="-DWOLFSSL_AES_DIRECT -DWOLFSSL_AES_COUNTER -DHAVE_AES_ECB -DHAVE_AESCCM"
modes="${modes} -DWOLFSSL_AES_XTS -DWOLFSSL_CMAC -DWOLFSSL_AES_CFB"
modes="${modes} -DWOLFSSL_AES_OFB -DWOLFSSL_AES_CTS"
gcm_modes="-DWOLFSSL_AESGCM_STREAM -DWOLFSSL_AESGCM_SIV"

x64="-D__x86_64__"
a64="-D__aarch64__"
a32="-D__arm__"
rv="-D__riscv -D__riscv_xlen=64"
gcm="-DHAVE_AESGCM"

echo "== C core"
check no  yes ${x64} ${gcm}
check yes yes ${x64} ${gcm} -DWOLFSSL_AES_TOUCH_LINES
check yes yes ${x64} ${gcm} -DWC_AES_BITSLICED -DHAVE_AES_ECB
check no  no  ${x64}
check no  no  ${x64} ${gcm} -DWC_NO_CACHE_RESISTANT
check no  no  ${x64} ${gcm} -DAES_GCM_GMULT_NO_CACHE_RESIST
check no  no  ${x64} ${gcm} -DGCM_TABLE
check no  no  ${x64} ${gcm} -DGCM_TABLE_4BIT
check no  yes ${x64} ${gcm} -DGCM_SMALL
check no  no  ${x64} ${gcm} -DGCM_SMALL -DAES_GCM_GMULT_NO_CACHE_RESIST
check no  yes ${x64} ${gcm} -DGCM_WORD32
check no  no  ${x64} ${gcm} -DGCM_WORD32 -DGCM_TABLE
check no  no  ${x64} ${gcm} -DGCM_WORD32 -DGCM_TABLE_4BIT
check no  yes ${x64} ${gcm} -DGCM_WORD32 -DGCM_SMALL
check no  no  ${x64} ${gcm} -DGCM_WORD32 -DWC_NO_CACHE_RESISTANT
check no  yes ${x64} ${gcm} -DGCM_INT_MUL
check no  no  ${x64} -DNO_AES -DWOLFSSL_AES_TOUCH_LINES
check yes no  ${x64} ${gcm} -DWOLFSSL_AES_TOUCH_LINES -DWC_NO_CACHE_RESISTANT

echo "== AES-NI (C core when the CPU lacks it)"
check no  yes ${x64} ${gcm} -DWOLFSSL_AESNI
check yes yes ${x64} ${gcm} -DWOLFSSL_AESNI -DWOLFSSL_AES_TOUCH_LINES
check yes no  ${x64} ${gcm} -DWOLFSSL_AESNI -DWOLFSSL_AES_TOUCH_LINES \
    -DWC_NO_CACHE_RESISTANT
check yes no  ${x64} ${gcm} -DWOLFSSL_AESNI -DWOLFSSL_AES_TOUCH_LINES \
    -DGCM_TABLE_4BIT

echo "== AArch64 assembly"
check no  yes ${a64} ${gcm} -DWOLFSSL_ARMASM
check yes yes ${a64} ${gcm} -DWOLFSSL_ARMASM \
    -DWOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP
check no  no  ${a64} ${gcm} -DWOLFSSL_ARMASM \
    -DWOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP -DWOLFSSL_ARMASM_NO_NEON
check yes yes ${a64} ${gcm} -DWOLFSSL_ARMASM \
    -DWOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP -DGCM_TABLE
check yes yes ${a64} ${gcm} -DWOLFSSL_ARMASM \
    -DWOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP -DGCM_SMALL
check yes no  ${a64} ${gcm} -DWOLFSSL_ARMASM \
    -DWOLFSSL_ARMASM_NEON_NO_TABLE_LOOKUP -DGCM_SMALL \
    -DAES_GCM_GMULT_NO_CACHE_RESIST
check no  yes ${a64} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_AES_TOUCH_LINES \
    -DWOLFSSL_ARMASM_NO_BASE_IMPL

echo "== 32-bit Arm C core"
check no  yes ${a32} ${gcm} -D__ARM_ARCH=5
check no  no  ${a32} ${gcm} -D__ARM_ARCH=5 -DGCM_INT_MUL
check no  yes ${a32} ${gcm} -D__ARM_ARCH=7 -DGCM_INT_MUL

echo "== Cores with an unknown line or read width"
check no  yes -D__mips__ ${gcm} -DWOLFSSL_AES_TOUCH_LINES
check no  yes -D__i386__ ${gcm} -DWOLFSSL_AES_TOUCH_LINES
check no  yes ${a32} ${gcm} -DWOLFSSL_AES_TOUCH_LINES -D__ARM_ARCH_PROFILE=82
check yes yes -D__mips__ ${gcm} -DWOLFSSL_AES_TOUCH_LINES -DWC_CACHE_LINE_SZ=16

echo "== 16-bit CPU (software 32-bit multiply)"
check no  yes ${gcm} -DWC_16BIT_CPU -DWOLFSSL_SP_ALLOW_16BIT_CPU
check no  no  ${gcm} -DWC_16BIT_CPU -DWOLFSSL_SP_ALLOW_16BIT_CPU \
    -DGCM_INT_MUL

# Thumb-1-only M-profile multiplies 32x32->32; the layout must not follow DSP.
m="${a32} ${gcm} -DGCM_INT_MUL -D__ARM_ARCH_PROFILE=77"
check_im 32  ${m} -D__ARM_ARCH=8 -D__ARM_ARCH_ISA_THUMB=1
check_im 32  ${m} -D__ARM_ARCH=7 -D__ARM_ARCH_ISA_THUMB=2 -D__ARM_ARCH_7M__
check_im 32W ${m} -D__ARM_ARCH=7 -D__ARM_ARCH_ISA_THUMB=2
check_im 32W ${m} -D__ARM_ARCH=7 -D__ARM_ARCH_ISA_THUMB=2 -D__ARM_FEATURE_DSP

echo "== 32-bit Arm assembly"
check no  no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_THUMB2 \
    -DWOLFSSL_ARMASM_NO_HW_CRYPTO
check yes no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_THUMB2 \
    -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_AES_TOUCH_LINES \
    -D__ARM_ARCH_7EM__ -D__ARM_ARCH_PROFILE=77
# Cortex-M without the settings.h stride cap (armcc names) needs a stride.
check no  no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_THUMB2 \
    -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_AES_TOUCH_LINES
check yes no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_THUMB2 \
    -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DWOLFSSL_AES_TOUCH_LINES \
    -DWC_CACHE_LINE_SZ=8
check yes no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO \
    -DWOLFSSL_AES_TOUCH_LINES -D__ARM_ARCH_PROFILE=65
check no  no  ${a32} ${gcm} -DWOLFSSL_ARMASM
check yes no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_BASE_IMPL
check no  no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_NO_HW_CRYPTO \
    -DWOLFSSL_ARMASM_NO_BASE_IMPL
check no  no  ${a32} ${gcm} -DWOLFSSL_ARMASM -DWOLFSSL_ARMASM_THUMB2 \
    -DWOLFSSL_ARMASM_NO_HW_CRYPTO -DGCM_SMALL

echo "== RISC-V"
check no  yes ${rv} ${gcm}
check yes yes ${rv} ${gcm} -DWC_CACHE_LINE_SZ=32
check no  yes ${rv} ${gcm} -DWOLFSSL_AES_NO_TOUCH_LINES
check no  no  ${rv} ${gcm} -DWC_NO_CACHE_RESISTANT
check yes yes ${rv} ${gcm} -DWC_AES_BITSLICED -DHAVE_AES_ECB
check no  no  ${rv} ${gcm} -DGCM_INT_MUL
check no  yes ${rv} ${gcm} -DGCM_INT_MUL -D__riscv_zkt
check no  no  ${rv} ${gcm} -DWOLFSSL_RISCV_ASM
check no  no  ${rv} ${gcm} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM
check yes yes ${rv} ${gcm} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM -D__riscv_zkt
check no  no  ${rv} ${gcm} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_VECTOR_CRYPTO_ASM
check yes yes ${rv} ${gcm} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_VECTOR_CRYPTO_ASM -D__riscv_zvkt
check no  no  ${rv} ${gcm} -DWOLFSSL_RISCV_ASM \
    -DWOLFSSL_RISCV_VECTOR_CRYPTO_ASM -DWOLFSSL_RISCV_SCALAR_CRYPTO_ASM \
    -D__riscv_zvkt
check no  yes -D__riscv -D__riscv_xlen=32 ${gcm}
check yes yes -D__riscv -D__riscv_xlen=32 ${gcm} -DWC_CACHE_LINE_SZ=8
check_touch yes ${rv}
check_touch no  ${rv} -DWOLFSSL_RISCV_ASM
check_touch no  ${x64}

echo "== PowerPC assembly"
check no  no  -D__powerpc64__ ${gcm} -DWOLFSSL_PPC64_ASM \
    -DWOLFSSL_AES_TOUCH_LINES
check no  no  -D__powerpc64__ ${gcm} -DWOLFSSL_PPC64_ASM -DGCM_SMALL

echo "== Hardware and offload backends"
check no  no  ${a32} ${gcm} -DFREESCALE_MMCAU -DWOLFSSL_AES_TOUCH_LINES
for engine in -DFREESCALE_LTC -DWOLFSSL_PIC32MZ_CRYPT -DWOLFSSL_ESP32_CRYPT \
              -DWOLFSSL_SILABS_SE_ACCEL -DWOLFSSL_PSOC6_CRYPTO -DWOLFSSL_SCE \
              -DHAVE_COLDFIRE_SEC -DSTM32_CRYPTO -DWOLFSSL_IMX6_CAAM \
              -DWOLFSSL_SECO_CAAM -DWOLFSSL_NXP_HASHCRYPT_AES \
              -DWOLFSSL_MAXQ10XX_CRYPTO -DWOLFSSL_MAX3266X \
              -DWOLFSSL_MAX3266X_OLD -DWOLFSSL_TI_AM64X_R5 -DWOLFSSL_TI_CRYPT \
              -DWOLFSSL_XILINX_CRYPT -DWOLFSSL_RENESAS_FSPSM_CRYPTONLY \
              -DWOLFSSL_HAVE_PSA -DWOLFSSL_RENESAS_FSPSM_TLS \
              -DWOLFSSL_RENESAS_SCEPROTECT -DWOLFSSL_RENESAS_RSIP \
              -DWOLFSSL_RENESAS_TSIP_TLS -DWOLFSSL_RENESAS_TSIP_CRYPTONLY; do
    check_engine ${a32} ${gcm} -DWOLFSSL_AES_TOUCH_LINES "${engine}"
done
check_engine ${a32} ${gcm} -DWOLFSSL_AES_TOUCH_LINES -DWOLFSSL_SE050 \
    -DWOLFSSL_SE050_CRYPT
# QNX, ARIA and the sniffer's QAT and Octeon sync pick the AES device
# themselves.
for engine in -DHAVE_INTEL_QA_SYNC -DHAVE_CAVIUM_OCTEON_SYNC -DHAVE_ARIA; do
    check_engine ${x64} ${gcm} -DWOLFSSL_AES_TOUCH_LINES -DWOLF_CRYPTO_CB \
        "${engine}"
done
check_engine ${a64} ${gcm} -DWOLFSSL_AES_TOUCH_LINES -DWOLFSSL_CAAM \
    -DWOLFSSL_QNX_CAAM -DWOLF_CRYPTO_CB
check no  no  ${x64} ${gcm} -DWOLFSSL_AFALG -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DWOLFSSL_KCAPI_AES -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DWOLFSSL_DEVCRYPTO -DWOLFSSL_DEVCRYPTO_AES \
    -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_ONLY_AES
check no  no  ${x64} ${gcm} -DWOLFSSL_ASYNC_CRYPT -DWOLFSSL_ASYNC_CRYPT_SW \
    -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DWOLFSSL_DEVCRYPTO -DWOLFSSL_DEVCRYPTO_CBC \
    -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${a64} ${gcm} -DWOLFSSL_AFALG_XILINX -DWOLFSSL_AFALG_XILINX_AES \
    -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${a32} ${gcm} -DWOLFSSL_IMXRT_DCP -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DHAVE_CUDA -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DWOLFSSL_MICROCHIP_TA100 \
    -DWOLFSSL_MICROCHIP_AESGCM -DWOLFSSL_AES_TOUCH_LINES
check no  no  ${x64} ${gcm} -DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_FIND \
    -DWOLFSSL_AES_TOUCH_LINES
# Per-object crypto callbacks are outside what the flags describe.
check yes yes ${x64} ${gcm} -DWOLF_CRYPTO_CB -DWOLFSSL_AES_TOUCH_LINES

echo "== Derived only"
check_error "are derived" ${x64} -DWC_AES_BLOCK_CT
check_error "are derived" ${x64} -DWC_AES_GHASH_CT

if [ "${fails}" -ne 0 ]; then
    echo "${fails} case(s) failed"
    exit 1
fi
echo "all cases passed"
