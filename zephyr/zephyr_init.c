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

/* The module needs no boot-time SYS_INIT hook of its own: wolfCrypt_Init() and
 * the DRBG seed both happen lazily. The EdgeLock port is the exception - it
 * brings up a peripheral and arms an interrupt, which is worth doing at boot
 * rather than inside whichever call happens to be first. */

/* Key the hook off WOLFSSL_ELS_PKC, not CONFIG_WOLFSSL_ELS_PKC: a user-supplied
 * settings file is authoritative, so the Kconfig symbol can be set while the
 * port itself compiles to nothing. Include settings.h first to get it. */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ELS_PKC)

#include <errno.h>

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include <wolfssl/wolfcrypt/wc_port.h>

LOG_MODULE_REGISTER(wolfssl_els_pkc, CONFIG_WOLFSSL_LOG_LEVEL);

static int wolfssl_els_pkc_init(void)
{
    int ret;

    /* This is what brings the EdgeLock up and registers its callback. Log the
     * failure rather than rely on the return value: Zephyr passes a non-device
     * SYS_INIT result only to a trace hook, so it would otherwise leave no
     * evidence of software-only operation. */
    ret = wolfCrypt_Init();
    if (ret != 0) {
        LOG_ERR("wolfCrypt_Init failed: %d", ret);
        return -EIO;
    }

    return 0;
}

/* POST_KERNEL: wolfCrypt_Init() takes mutexes and may allocate, so the kernel
 * has to be up. Priority 99 is late within that level, which is what puts this
 * after the SoC and clock initialisation the ELS needs. */
SYS_INIT(wolfssl_els_pkc_init, POST_KERNEL, 99);

#endif /* WOLFSSL_ELS_PKC */
