MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 0x00040000   /* 256 KB, m33mu rw612 */
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 0x00080000   /* 512 KB, m33mu rw612 */
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .text :
    {
        *(.text*)
        *(.rodata*)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)
    } > FLASH

    .preinit_array :
    {
        __preinit_array_start = .;
        KEEP(*(.preinit_array*))
        __preinit_array_end = .;
    } > FLASH

    .init_array :
    {
        __init_array_start = .;
        KEEP(*(.init_array*))
        __init_array_end = .;
    } > FLASH

    .fini_array :
    {
        __fini_array_start = .;
        KEEP(*(.fini_array*))
        __fini_array_end = .;
    } > FLASH

    .data :
    {
        _sdata = .;
        *(.data*)
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > RAM

    /* Everything left over is heap. newlib reaches it through _sbrk() in
     * syscalls.c; picolibc wants these two symbols by name. Defining both
     * keeps the firmware buildable with either toolchain. */
    . = ALIGN(8);
    end = .;
    _end = .;
    __heap_start = .;
    __heap_end = ORIGIN(RAM) + LENGTH(RAM) - 0x4000;   /* leave 16 KB of stack */
}
