#include <stdio.h>
#include <unicorn/unicorn.h>

/* ARM: mov r0, #5 / mov r1, #3 / add r0, r0, r1 */
static const unsigned char ARM_CODE[] = {
    0x05, 0x00, 0xa0, 0xe3, 0x03, 0x10, 0xa0, 0xe3, 0x01, 0x00, 0x80, 0xe0,
};

#define ADDRESS 0x10000

int main(void) {
    uc_engine *uc;
    uc_err err;
    int r0;

    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("uc_open failed: %s\n", uc_strerror(err));
        return 1;
    }

    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
    uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE));

    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE), 0, 0);
    if (err != UC_ERR_OK) {
        printf("uc_emu_start failed: %s\n", uc_strerror(err));
        uc_close(uc);
        return 1;
    }

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    printf("r0 = %d (expected 8)\n", r0);

    uc_close(uc);
    return (r0 == 8) ? 0 : 1;
}
