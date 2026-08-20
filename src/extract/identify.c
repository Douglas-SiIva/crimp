#include "extract_internal.h"

int crimp_fs_identify(const char *path, crimp_fs_info *out) {
    if (crimp_squashfs_identify(path, out) == 0) {
        return 0;
    }

    /* JFFS2 (#8) and cramfs (#9) go here once implemented. */

    return -1;
}

const char *crimp_fs_compression_name(crimp_fs_type type, uint16_t compression) {
    switch (type) {
        case CRIMP_FS_SQUASHFS:
            return crimp_squashfs_compression_name(compression);
        default:
            return "unknown";
    }
}
