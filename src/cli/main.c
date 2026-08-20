#include "crimp/extract.h"

#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <firmware-image>\n", argv[0]);
        return 1;
    }

    crimp_fs_info info;
    if (crimp_fs_identify(argv[1], &info) != 0) {
        fprintf(stderr, "%s: filesystem not recognized\n", argv[1]);
        return 1;
    }

    printf("filesystem:    squashfs\n");
    printf("inodes:        %u\n", info.inode_count);
    printf("block_size:    %u\n", info.block_size);
    printf("compression:   %s\n", crimp_fs_compression_name(info.type, info.compression));
    printf("bytes_used:    %llu\n", (unsigned long long)info.bytes_used);

    /* No detectors registered yet (see issues #10-#14) — extraction-only for now. */

    return 0;
}
