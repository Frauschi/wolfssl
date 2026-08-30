/* zephyr_init.c
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

/* The wolfSSL Zephyr module needs no boot-time SYS_INIT hook. wolfCrypt's
 * Hash-DRBG is seeded on demand by wc_GenerateSeed() -- which on Zephyr draws
 * from the hardware entropy driver when one is present (see
 * wolfcrypt/src/random.c) -- and wolfCrypt_Init()/wolfSSL_Init() run lazily
 * from the first library call. This translation unit is kept (it is referenced
 * by the module CMakeLists) as the place for any future module init.
 *
 * The one exception is the NXP EdgeLock port, which does need a boot hook: its
 * crypto callback has to be registered with wolfCrypt before anything asks for
 * a cipher, and registration must happen *after* wolfCrypt_Init(), which zeroes
 * the callback device table. Calling wolfCrypt_Init() here makes that ordering
 * explicit rather than depending on which library call happens to run first. */

/* Key the hook off WOLFSSL_ELS_PKC, not CONFIG_WOLFSSL_ELS_PKC. A user-supplied
 * settings file is authoritative and the Kconfig build-profile knobs are not
 * applied on top of it, so the Kconfig symbol can be set while the port itself
 * compiles to nothing. Including settings.h first and testing the macro the
 * port actually uses keeps the two in step either way. */
#include <wolfssl/wolfcrypt/settings.h>

/* Both symbols, deliberately. The C macro alone is what the port keys off,
 * but CMakeLists gates the port sources on the Kconfig symbol - so a user
 * settings file that defines the macro without the Kconfig option would
 * compile this hook against a port that is not in the build, and the failure
 * would be an undefined reference to a private symbol rather than anything
 * naming the missing option. */
#if defined(WOLFSSL_ELS_PKC) && defined(CONFIG_WOLFSSL_ELS_PKC)

#include <errno.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>

static int wolfssl_els_pkc_init(void)
{
    int ret;

    /* wc_CryptoCb_Init() runs from here and wipes the device table, so the
     * callback cannot be registered before it. */
    ret = wolfCrypt_Init();
    if (ret != 0) {
        return -EIO;
    }

    ret = wc_ElsPkc_Init();
    if (ret != 0) {
        return -EIO;
    }

    return 0;
}

/* POST_KERNEL: wolfCrypt_Init() takes mutexes and may allocate, so the kernel
 * has to be up. Late in the priority range so the els_pkc module's own SoC
 * bring-up has already run. */
SYS_INIT(wolfssl_els_pkc_init, POST_KERNEL, 99);

#endif /* WOLFSSL_ELS_PKC */
