/* user_settings_wolfssh.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


/* To use the rename file to user_settings.h and define WOLFSSL_USER_SETTINGS */

/* Started from the following configure and hand tuned, organized and commented:
./configure --enable-wolfssh --enable-sp=small --enable-sp-math \
--disable-sp-asm --disable-asm --disable-sys-ca-certs --enable-aesgcm=small \
--enable-cryptonly --disable-sha3 --disable-chacha --disable-poly1305 \
--disable-md5 --disable-error-queue-per-thread --disable-pkcs12 \
--disable-errorstrings --disable-sni --disable-sha224
make
*/

/* Tested using:
cp ./examples/configs/user_settings_wolfssh.h user_settings.h
cp ./examples/configs/user_settings_wolfssh.h ../wolfSSH/user_settings.h

wolfSSL:
./configure --enable-usersettings --disable-examples CFLAGS="-Os"
make
sudo make install

wolfSSH:
./configure --enable-scp --disable-shared --disable-term \
    CFLAGS="-DWOLFSSL_USER_SETTINGS -Os"
make
*/

#ifndef WOLFSSL_USER_SETTINGS_SSH_H
#define WOLFSSL_USER_SETTINGS_SSH_H

#ifdef __cplusplus
extern "C" {
#endif

/* Platform */
#if 0 /* Threading and filesystem required for wolfSSH tests \
       * Can be set for wolfSSH library only use */
    #define SINGLE_THREADED
    #define NO_FILESYSTEM
#endif

/* Features */
#define WOLFSSL_WOLFSSH
#if 1
    #define WOLFCRYPT_ONLY /* no TLS */
#endif
#define HAVE_HASHDRBG
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_PUBLIC_MP

/* Timing Resistance */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Asymmetric */
#undef NO_RSA
#if 1 /* DH */
    #undef NO_DH
    #define HAVE_DH_DEFAULT_PARAMS
    #define HAVE_FFDHE_2048
#else
    #define NO_DH
#endif
#define HAVE_ECC
#ifdef HAVE_ECC
    #if 0 /* optional ECC SHAMIR speedup */
        #define ECC_SHAMIR
    #endif
    #define ECC_USER_CURVES
    #define HAVE_ECC384
    #define HAVE_ECC521
#endif

/* Symmetric AES CBC/GCM */
#undef NO_AES_CBC
#if 1 /* GCM */
    #define HAVE_AESGCM
    #define GCM_SMALL
#endif

/* Hashing SHA-1, SHA2-256/384/512 */
#undef NO_SHA
#undef NO_SHA256
#if 1
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512
#endif


/* Math */
/* Multi Precision (MP): Enable support for uncommon key sizes / curves */
#if 0
    #define WOLFSSL_SP_MATH_ALL
#endif

/* Single Precision (SP) Math */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL

#if !defined(NO_RSA) || !defined(NO_RSA)
    #undef WOLFSSL_SP_NO_2048 /* 2048-bit */
    #undef WOLFSSL_SP_NO_3072 /* 3072-bit */
    #define WOLFSSL_SP_4096   /* 4096-bit */

    #ifndef NO_RSA
        #define WOLFSSL_HAVE_SP_RSA
    #endif
    #ifndef NO_DH
        #define WOLFSSL_HAVE_SP_DH
    #endif
#endif
#ifdef HAVE_ECC
    #define WOLFSSL_HAVE_SP_ECC

    #undef WOLFSSL_SP_NO_256
    #ifdef HAVE_ECC384
        #define WOLFSSL_SP_384
    #endif
    #ifdef HAVE_ECC521
        #define WOLFSSL_SP_521
    #endif
#endif

#ifndef WOLFCRYPT_ONLY
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_ENCRYPT_THEN_MAC
#endif

/* Disable Algorithms */
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_PSK
#define NO_PKCS12
#define NO_PWDBASED
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* Disable Features */
#define NO_ERROR_STRINGS
#define WC_NO_ASYNC_THREADING
#define NO_DES3_TLS_SUITES
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12

#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_USER_SETTINGS_SSH_H */
