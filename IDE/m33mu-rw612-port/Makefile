# Bare-metal EdgeLock port checks for m33mu --cpu rw612.
#
# Links the libwolfssl.a produced by the cross build in the repository root,
# so this exercises the same library CI compiles rather than a separate list of
# sources. Build that first:
#
#   ./configure --host=arm-none-eabi --disable-shared --enable-static \
#       --enable-cryptonly --enable-cryptocb \
#       --enable-cryptocbutils=copy,free,keystore \
#       --enable-ecc --enable-aesgcm --enable-cmac \
#       --with-els-pkc=$(ELS_PKC) --with-mcux-sdk=$(MCUX_SDK) \
#       --disable-filesystem --enable-singlethreaded \
#       --disable-examples --disable-crypttests \
#       CFLAGS="-mcpu=cortex-m33+nodsp -mthumb -Os -ffreestanding" \
#       CPPFLAGS="-DWOLFSSL_NO_SOCK -DWOLFSSL_USER_IO -DNO_WRITEV -DNO_DEV_RANDOM"
#   make
#
# then, from here:
#
#   make ELS_PKC=/path/to/els_pkc MCUX_SDK=/path/to/mcux-sdk-ng
#   m33mu --cpu rw612 --expect-bkpt 0x7f --timeout 30 app.bin

CROSS   ?= arm-none-eabi-
CC      := $(CROSS)gcc
OBJCOPY ?= $(CROSS)objcopy
NM      ?= $(CROSS)nm
SIZE    ?= $(CROSS)size

WOLFSSL_ROOT ?= ../..
ELS_PKC      ?= $(WOLFSSL_ROOT)/../../els_pkc
MCUX_SDK     ?= $(WOLFSSL_ROOT)/../hal/nxp/mcux/mcux-sdk-ng

LIBWOLFSSL := $(WOLFSSL_ROOT)/src/.libs/libwolfssl.a

# +nodsp: the vendor CMSIS core_cm33.h rejects the build without it.
CFLAGS := -mcpu=cortex-m33+nodsp -mthumb -mcmse -Os -ffreestanding
CFLAGS += -fdata-sections -ffunction-sections -g -ggdb -Wall -Wextra
# Take the configuration from the library's generated wolfssl/options.h, NOT
# from a user_settings.h of our own. The application must be built with exactly
# the feature defines the library was built with; a mismatch changes struct
# layouts and corrupts memory at run time rather than failing to compile.
CFLAGS += -DCPU_RW612ETA2I -DWOLFSSL_USE_OPTIONS_H
CFLAGS += -I. -I$(WOLFSSL_ROOT)

ELS_INCS := \
	-I$(ELS_PKC)/src/inc \
	-I$(ELS_PKC)/src/compiler \
	-I$(ELS_PKC)/src/platforms/rw61x \
	-I$(ELS_PKC)/src/platforms/rw61x/inc \
	-I$(ELS_PKC)/src/platforms/rw61x/cmsis_cortex_m_5_5_1/inc \
	-I$(ELS_PKC)/includes/platform/rw61x \
	$(addprefix -I,$(wildcard $(ELS_PKC)/src/comps/*/inc)) \
	$(addprefix -I,$(wildcard $(ELS_PKC)/src/comps/*/inc/internal)) \
	-I$(MCUX_SDK)/devices/Wireless/RW/RW612 \
	-I$(MCUX_SDK)/devices/Wireless/RW/RW612/drivers \
	-I$(MCUX_SDK)/devices/Wireless/RW/periph \
	-I$(MCUX_SDK)/drivers/common

LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections -Wl,-Map=app.map

APP_SRCS  := main.c ivt.c syscalls.c els_stubs.c els_stub_descriptors.c
APP_OBJS  := $(patsubst %.c,build/%.o,$(APP_SRCS))

all: app.bin

app.elf: $(APP_OBJS) target.ld $(LIBWOLFSSL)
	$(CC) $(CFLAGS) $(APP_OBJS) $(LDFLAGS) \
		-Wl,--start-group $(LIBWOLFSSL) -lc -lm -lgcc -lnosys -Wl,--end-group \
		-o $@
	$(SIZE) $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

# Only the stubs need the vendor headers; main.c reaches the port through
# wolfSSL's own header.
build/els_stubs.o build/els_stub_descriptors.o: CFLAGS += $(ELS_INCS)

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBWOLFSSL):
	@echo "error: $(LIBWOLFSSL) not found. Cross-build wolfSSL first (see the"
	@echo "       configure line at the top of this Makefile)."
	@false

symbols: app.elf
	$(NM) -n app.elf > app.sym

clean:
	rm -rf build app.elf app.bin app.map app.sym

.PHONY: all symbols clean
