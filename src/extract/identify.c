#include "extract_internal.h"

int crimp_fs_identify(const char *path, crimp_fs_info *out) {
    if (crimp_squashfs_identify(path, out) == 0) {
        return 0;
    }

    /* JFFS2 (#8) and cramfs (#9) go here once implemented. */

    return -1;
}

const char *crimp_fs_compression_name(crimp_fs_type type, uint16_t compression) {
    if (type == CRIMP_FS_SQUASHFS) {
        return crimp_squashfs_compression_name(compression);
    }
    return "unknown";
}

int crimp_fs_extract(const char *path, const char *output_dir) {
    crimp_squashfs_entry_list list;
    if (crimp_squashfs_extract(path, output_dir, &list) == 0) {
        crimp_squashfs_entry_list_free(&list);
        return 0;
    }

    /* JFFS2 (#8) and cramfs (#9) go here once implemented. */

    return -1;
}
