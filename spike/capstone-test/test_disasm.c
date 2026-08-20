#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>

/* ARM Thumb-2 bytes: a typical little-endian function prologue, common in IoT firmware */
static const unsigned char ARM_CODE[] = {
    0x80, 0xb5,             /* push {r7, lr} */
    0x82, 0xb0,             /* sub sp, #8 */
    0x00, 0xaf,             /* add r7, sp, #0 */
    0x00, 0x20,             /* movs r0, #0 */
    0x00, 0xbf,             /* nop */
};

int main(void) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) {
        printf("cs_open failed\n");
        return 1;
    }

    count = cs_disasm(handle, ARM_CODE, sizeof(ARM_CODE), 0x1000, 0, &insn);
    if (count == 0) {
        printf("cs_disasm failed\n");
        cs_close(&handle);
        return 1;
    }

    printf("Disassembled %zu instructions:\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("0x%" PRIx64 ":\t%s\t\t%s\n",
               insn[i].address, insn[i].mnemonic, insn[i].op_str);
    }

    cs_free(insn, count);
    cs_close(&handle);
    return 0;
}
