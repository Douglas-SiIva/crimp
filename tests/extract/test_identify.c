#include "crimp/extract.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirrors the on-disk SquashFS 4.0 superblock layout (96 bytes, documented
 * in .claude/skills/squashfs-extraction/SKILL.md) — not the internal struct
 * in squashfs.c, which is private to that file. Built at runtime rather
 * than committed as a binary fixture, same rationale as the other tests. */
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
} test_squashfs_superblock;
#pragma pack(pop)

static void write_superblock(const char *path, uint16_t compression) {
    test_squashfs_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.inodes = 42;
    sb.block_size = 131072;
    sb.fragments = 3;
    sb.compression = compression;
    sb.block_log = 17;
    sb.s_major = 4;
    sb.s_minor = 0;
    sb.bytes_used = 123456;

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }
    fwrite(&sb, sizeof(sb), 1, f);
    fclose(f);
}

int main(void) {
    const char *good_path = "test_fixture_squashfs.img";
    write_superblock(good_path, 4 /* xz */);

    crimp_fs_info info;
    if (crimp_fs_identify(good_path, &info) != 0) {
        fprintf(stderr, "FAIL: expected identify to succeed on a valid superblock\n");
        return 1;
    }
    if (info.type != CRIMP_FS_SQUASHFS || info.inode_count != 42 ||
        info.block_size != 131072 || info.bytes_used != 123456) {
        fprintf(stderr,
                "FAIL: unexpected fields (type=%d inode_count=%u block_size=%u "
                "bytes_used=%llu)\n",
                info.type, info.inode_count, info.block_size,
                (unsigned long long)info.bytes_used);
        return 1;
    }
    if (strcmp(crimp_fs_compression_name(info.type, info.compression), "xz") != 0) {
        fprintf(stderr, "FAIL: expected compression name 'xz'\n");
        return 1;
    }
    if (strcmp(crimp_fs_compression_name(CRIMP_FS_SQUASHFS, 1), "gzip") != 0) {
        fprintf(stderr, "FAIL: expected compression name 'gzip'\n");
        return 1;
    }
    if (strcmp(crimp_fs_compression_name(CRIMP_FS_SQUASHFS, 99), "unknown") != 0) {
        fprintf(stderr, "FAIL: expected 'unknown' for an unrecognized compressor id\n");
        return 1;
    }
    static const struct {
        uint16_t id;
        const char *name;
    } compressors[] = {
        {2, "lzma"}, {3, "lzo"}, {5, "lz4"}, {6, "zstd"},
    };
    for (size_t i = 0; i < sizeof(compressors) / sizeof(compressors[0]); i++) {
        if (strcmp(crimp_fs_compression_name(CRIMP_FS_SQUASHFS, compressors[i].id),
                   compressors[i].name) != 0) {
            fprintf(stderr, "FAIL: expected compression name '%s' for id %u\n",
                    compressors[i].name, compressors[i].id);
            return 1;
        }
    }
    if (strcmp(crimp_fs_compression_name(CRIMP_FS_UNKNOWN, 0), "unknown") != 0) {
        fprintf(stderr, "FAIL: expected 'unknown' compression name for CRIMP_FS_UNKNOWN\n");
        return 1;
    }

    /* A file with the right size but wrong magic must fail cleanly, not
     * misidentify or crash. */
    const char *bad_path = "test_fixture_not_squashfs.bin";
    FILE *bf = fopen(bad_path, "wb");
    if (!bf) {
        fprintf(stderr, "failed to create fixture: %s\n", bad_path);
        return 1;
    }
    char junk[96];
    memset(junk, 0, sizeof(junk));
    fwrite(junk, 1, sizeof(junk), bf);
    fclose(bf);

    crimp_fs_info bad_info;
    if (crimp_fs_identify(bad_path, &bad_info) == 0) {
        fprintf(stderr, "FAIL: expected identify to fail on non-squashfs data\n");
        return 1;
    }

    /* A path that doesn't exist at all must also fail cleanly. */
    if (crimp_fs_identify("test_fixture_does_not_exist.bin", &bad_info) == 0) {
        fprintf(stderr, "FAIL: expected identify to fail on a missing file\n");
        return 1;
    }

    printf("PASS: crimp_fs_identify + crimp_fs_compression_name work end-to-end\n");
    return 0;
}
