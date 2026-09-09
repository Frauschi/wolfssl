# Bare-metal EdgeLock port checks for m33mu --cpu rw612. Links the
# libwolfssl.a cross-built in the repository root; see README.md.

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
# Use the library's options.h: the feature defines must match its build.
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
