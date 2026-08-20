#include <stdint.h>
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

static const char *compression_name(uint16_t id) {
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

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <squashfs-image>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    squashfs_superblock sb;
    if (fread(&sb, sizeof(sb), 1, f) != 1) {
        fprintf(stderr, "failed to read superblock\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    if (memcmp(&sb.magic, "hsqs", 4) != 0) {
        fprintf(stderr, "not a squashfs image (magic mismatch: 0x%08x)\n", sb.magic);
        return 1;
    }

    printf("SquashFS %u.%u\n", sb.s_major, sb.s_minor);
    printf("  inodes:               %u\n", sb.inodes);
    printf("  block_size:           %u\n", sb.block_size);
    printf("  fragments:            %u\n", sb.fragments);
    printf("  compression:          %s\n", compression_name(sb.compression));
    printf("  bytes_used:           %llu\n", (unsigned long long)sb.bytes_used);
    printf("  root_inode:           0x%llx\n", (unsigned long long)sb.root_inode);
    printf("  inode_table_start:    0x%llx\n", (unsigned long long)sb.inode_table_start);
    printf("  directory_table_start:0x%llx\n", (unsigned long long)sb.directory_table_start);
    printf("  fragment_table_start: 0x%llx\n", (unsigned long long)sb.fragment_table_start);
    printf("  id_table_start:       0x%llx\n", (unsigned long long)sb.id_table_start);

    return 0;
}
