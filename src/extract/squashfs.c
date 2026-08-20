#include "extract_internal.h"

#include <stdio.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t inodes;
    uint32_t mkfs_time;
    uint32_t block_size;
    uint32_t fragments;
    uint16_t compression;
    uint16_t block_log;
    uint16_t flags;
    uint16_t no_ids;
    uint16_t s_major;
    uint16_t s_minor;
    uint64_t root_inode;
    uint64_t bytes_used;
    uint64_t id_table_start;
    uint64_t xattr_id_table_start;
    uint64_t inode_table_start;
    uint64_t directory_table_start;
    uint64_t fragment_table_start;
    uint64_t lookup_table_start;
} squashfs_superblock;
#pragma pack(pop)

int crimp_squashfs_identify(const char *path, crimp_fs_info *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    squashfs_superblock sb;
    size_t read = fread(&sb, sizeof(sb), 1, f);
    fclose(f);

    if (read != 1 || memcmp(&sb.magic, "hsqs", 4) != 0) {
        return -1;
    }

    out->type = CRIMP_FS_SQUASHFS;
    out->inode_count = sb.inodes;
    out->block_size = sb.block_size;
    out->compression = sb.compression;
    out->bytes_used = sb.bytes_used;
    return 0;
}

const char *crimp_squashfs_compression_name(uint16_t id) {
    switch (id) {
        case 1: return "gzip";
        case 2: return "lzma";
        case 3: return "lzo";
        case 4: return "xz";
        case 5: return "lz4";
        case 6: return "zstd";
        default: return "unknown";
    }
}
