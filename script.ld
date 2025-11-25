SECTIONS
{
    .text 0x0 : ALIGN(1) SUBALIGN(1)
    {
        *(.text$mainCRTStartup)
        *(.text*)
        *(.data*)
        *(.rdata*)
    }
}