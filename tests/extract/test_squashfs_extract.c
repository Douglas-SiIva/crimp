#include "extract_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#ifndef FIXTURE_PATH
#error "FIXTURE_PATH must be defined by the build (see CMakeLists.txt)"
#endif
#ifndef OUTPUT_DIR
#error "OUTPUT_DIR must be defined by the build (see CMakeLists.txt)"
#endif

/* Ground truth captured from `unsquashfs -d` + sha256sum against this
 * fixture — see tests/fixtures/README.md for how it was generated. */
static const char EXPECTED_CONFIG[] = "hello=world\n";
static const char EXPECTED_PASSWD[] = "root:x:0:0:root:/root:/bin/sh\n";
static const char EXPECTED_BUSYBOX[] = "FAKE_BUSYBOX_BINARY_CONTENT_1234567890";
static const char EXPECTED_DEEP[] = "nested file content here";
#define BIGFILE_SIZE 11000

static unsigned char *read_whole_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (n != (size_t)size) {
        free(buf);
        return NULL;
    }
    *out_len = n;
    return buf;
}

static int check_file(const char *rel_path, const void *expected, size_t expected_len) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", OUTPUT_DIR, rel_path);
    size_t len = 0;
    unsigned char *buf = read_whole_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: could not read extracted file '%s'\n", path);
        return 0;
    }
    int ok = (len == expected_len) && (memcmp(buf, expected, expected_len) == 0);
    if (!ok) {
        fprintf(stderr, "FAIL: '%s' content mismatch (got %zu bytes, expected %zu)\n", path, len,
                expected_len);
    }
    free(buf);
    return ok;
}

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
} test_superblock;
#pragma pack(pop)

static void fw16(FILE *f, uint16_t v) { fwrite(&v, sizeof(v), 1, f); }
static void fw32(FILE *f, uint32_t v) { fwrite(&v, sizeof(v), 1, f); }

/* A single-file image whose one data block is marked compressed but holds
 * bytes that aren't a valid zlib stream - decompression fails partway
 * through extract_regular_file(), which must not leave a truncated
 * "corrupt.bin" behind. Layout (all single-block, uncompressed metadata,
 * sizes hand-computed and asserted against what's actually written): a
 * root dir inode + one basic file inode in the inode table, one directory
 * entry naming it "corrupt.bin", then the garbage block data itself. */
static int build_corrupt_block_image(const char *path) {
    const uint32_t block_size = 4096;
    const uint16_t file_inode_len = 16 + 16 + 4;  /* header + basic-file fields + block_sizes[1] */
    const uint16_t root_inode_len = 16 + 16;      /* header + basic-dir fields */
    const uint16_t inode_blob_len = (uint16_t)(file_inode_len + root_inode_len);
    const char name[] = "corrupt.bin";
    const uint16_t name_len = (uint16_t)(sizeof(name) - 1);
    const uint16_t dir_entry_len = (uint16_t)(8 + name_len);
    const uint16_t dir_blob_len = (uint16_t)(12 + dir_entry_len);
    const uint8_t garbage[10] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.inodes = 2;
    sb.block_size = block_size;
    sb.block_log = 12;
    sb.s_major = 4;
    sb.root_inode = file_inode_len; /* root dir inode: block_index 0, offset = right after the file inode */
    sb.inode_table_start = sizeof(test_superblock);
    sb.directory_table_start = sb.inode_table_start + 2 + inode_blob_len;

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);

    /* Inode table: file inode first (offset 0), then root dir inode. */
    fw16(f, (uint16_t)(inode_blob_len | 0x8000)); /* uncompressed metadata block */
    fw16(f, 2);   /* type: basic file */
    fw16(f, 0);   /* perm */
    fw16(f, 0);   /* uid_idx */
    fw16(f, 0);   /* gid_idx */
    fw32(f, 0);   /* mtime */
    fw32(f, 2);   /* inode_number */
    fw32(f, 0);   /* blocks_start - patched conceptually below via content_blocks_start */
    fw32(f, 0xFFFFFFFFu); /* frag_index: none */
    fw32(f, 0);   /* block_offset (fragment) */
    fw32(f, block_size); /* file_size: exactly one full block */
    fw32(f, 10);  /* block_sizes[0]: size=10, bit 24 clear -> compressed */

    fw16(f, 1);   /* type: basic directory */
    fw16(f, 0);
    fw16(f, 0);
    fw16(f, 0);
    fw32(f, 0);
    fw32(f, 1);   /* inode_number */
    fw32(f, 0);   /* block_index */
    fw32(f, 1);   /* link_count */
    fw16(f, (uint16_t)(dir_blob_len + 3)); /* file_size (dir_size) */
    fw16(f, 0);   /* block_offset */
    fw32(f, 0);   /* parent_inode */

    /* Directory table: one header group, one entry naming the file inode. */
    fw16(f, (uint16_t)(dir_blob_len | 0x8000));
    fw32(f, 0);   /* count - 1 */
    fw32(f, 0);   /* start: inode table block_index */
    fw32(f, 0);   /* inode_number base */
    fw16(f, 0);   /* offset: file inode's in-block offset */
    fw16(f, 0);   /* inode_offset delta */
    fw16(f, 2);   /* type */
    fw16(f, (uint16_t)(name_len - 1));
    fwrite(name, 1, name_len, f);

    /* The file's one and only (garbage) data block. blocks_start above was
     * written as 0 because content_blocks_start must equal exactly this
     * file position - reopen and patch it now that we know the offset. */
    long content_blocks_start = ftell(f);
    fwrite(garbage, 1, sizeof(garbage), f);
    fclose(f);

    f = fopen(path, "r+b");
    if (!f) {
        return -1;
    }
    fseek(f, (long)(sizeof(test_superblock) + 2 + 16), SEEK_SET); /* file inode's blocks_start field */
    fw32(f, (uint32_t)content_blocks_start);
    fclose(f);
    return 0;
}

/* Root directory containing a single genuinely empty subdirectory
 * ("emptydir", dir_size < 4 - short-circuits before ever needing a real
 * directory-table location). Used to test make_directory()'s EEXIST
 * handling in isolation: with no children to fail on afterward, the old
 * "EEXIST always means success" behavior would make crimp_squashfs_extract
 * report bogus success even though "emptydir" collided with a pre-existing
 * regular file and nothing was actually extracted into a real directory. */
static int build_empty_dir_image(const char *path) {
    const uint16_t inode_len_each = 32; /* header(16) + basic-dir fields(16) */
    const char name[] = "emptydir";
    const uint16_t name_len = (uint16_t)(sizeof(name) - 1);
    const uint16_t dir_entry_len = (uint16_t)(8 + name_len);
    const uint16_t dir_blob_len = (uint16_t)(12 + dir_entry_len);

    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.inodes = 2;
    sb.block_size = 4096;
    sb.block_log = 12;
    sb.s_major = 4;
    sb.root_inode = inode_len_each; /* root dir inode is the second one, offset 32 */
    sb.inode_table_start = sizeof(test_superblock);
    sb.directory_table_start = sb.inode_table_start + 2 + (uint32_t)(inode_len_each * 2);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);

    fw16(f, (uint16_t)((inode_len_each * 2) | 0x8000));
    /* emptydir inode (offset 0) */
    fw16(f, 1);
    fw16(f, 0);
    fw16(f, 0);
    fw16(f, 0);
    fw32(f, 0);
    fw32(f, 2); /* inode_number */
    fw32(f, 0); /* block_index - never read, dir_size short-circuits first */
    fw32(f, 1); /* link_count */
    fw16(f, 0); /* file_size = 0: empty directory */
    fw16(f, 0); /* block_offset */
    fw32(f, 1); /* parent_inode */
    /* root inode (offset 32) */
    fw16(f, 1);
    fw16(f, 0);
    fw16(f, 0);
    fw16(f, 0);
    fw32(f, 0);
    fw32(f, 1); /* inode_number */
    fw32(f, 0); /* block_index */
    fw32(f, 1); /* link_count */
    fw16(f, (uint16_t)(dir_blob_len + 3));
    fw16(f, 0); /* block_offset */
    fw32(f, 0); /* parent_inode */

    fw16(f, (uint16_t)(dir_blob_len | 0x8000));
    fw32(f, 0); /* count - 1 */
    fw32(f, 0); /* start */
    fw32(f, 0); /* inode_number base */
    fw16(f, 0); /* offset: emptydir inode's in-block offset */
    fw16(f, 0);
    fw16(f, 1); /* type */
    fw16(f, (uint16_t)(name_len - 1));
    fwrite(name, 1, name_len, f);
    fclose(f);
    return 0;
}

/* A superblock claiming a block_size below the spec's 4096-byte minimum -
 * regression test for validate_block_size()'s lower bound. Only the
 * superblock needs to be well-formed; extraction must be rejected before
 * anything else in the file is even read. */
static int build_tiny_block_size_image(const char *path) {
    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.block_size = 2048; /* below MIN_SQUASHFS_BLOCK_SIZE, still a power of two */
    sb.block_log = 11;
    sb.s_major = 4;
    sb.root_inode = 0;
    sb.inode_table_start = sizeof(test_superblock);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);
    fclose(f);
    return 0;
}

/* Single-file image whose one data block is stored *uncompressed* (block
 * size field's bit 24 set) - the "not compressed" branch of
 * read_and_inflate_block(), never exercised by any other fixture here
 * (every other one uses gzip). Mirrors build_corrupt_block_image's layout,
 * but with valid raw bytes and the uncompressed flag set, so extraction
 * succeeds and the content can be verified byte-for-byte. */
static int build_uncompressed_block_image(const char *path) {
    const uint32_t block_size = 4096;
    const uint16_t file_inode_len = 16 + 16 + 4;
    const uint16_t root_inode_len = 16 + 16;
    const uint16_t inode_blob_len = (uint16_t)(file_inode_len + root_inode_len);
    const char name[] = "raw.bin";
    const uint16_t name_len = (uint16_t)(sizeof(name) - 1);
    const uint16_t dir_entry_len = (uint16_t)(8 + name_len);
    const uint16_t dir_blob_len = (uint16_t)(12 + dir_entry_len);

    uint8_t raw_data[4096];
    for (size_t i = 0; i < sizeof(raw_data); i++) {
        raw_data[i] = (uint8_t)(i % 251);
    }

    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.inodes = 2;
    sb.block_size = block_size;
    sb.block_log = 12;
    sb.s_major = 4;
    sb.root_inode = file_inode_len;
    sb.inode_table_start = sizeof(test_superblock);
    sb.directory_table_start = sb.inode_table_start + 2 + inode_blob_len;

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);

    fw16(f, (uint16_t)(inode_blob_len | 0x8000));
    fw16(f, 2);
    fw16(f, 0);
    fw16(f, 0);
    fw16(f, 0);
    fw32(f, 0);
    fw32(f, 2);
    fw32(f, 0); /* blocks_start - patched below */
    fw32(f, 0xFFFFFFFFu);
    fw32(f, 0);
    fw32(f, block_size);
    fw32(f, block_size | (1u << 24)); /* size = block_size, bit 24 set: uncompressed */

    fw16(f, 1);
    fw16(f, 0);
    fw16(f, 0);
    fw16(f, 0);
    fw32(f, 0);
    fw32(f, 1);
    fw32(f, 0);
    fw32(f, 1);
    fw16(f, (uint16_t)(dir_blob_len + 3));
    fw16(f, 0);
    fw32(f, 0);

    fw16(f, (uint16_t)(dir_blob_len | 0x8000));
    fw32(f, 0);
    fw32(f, 0);
    fw32(f, 0);
    fw16(f, 0);
    fw16(f, 0);
    fw16(f, 2);
    fw16(f, (uint16_t)(name_len - 1));
    fwrite(name, 1, name_len, f);

    long content_blocks_start = ftell(f);
    fwrite(raw_data, 1, sizeof(raw_data), f);
    fclose(f);

    f = fopen(path, "r+b");
    if (!f) {
        return -1;
    }
    fseek(f, (long)(sizeof(test_superblock) + 2 + 16), SEEK_SET);
    fw32(f, (uint32_t)content_blocks_start);
    fclose(f);
    return 0;
}

static int make_test_directory(const char *path) {
#if defined(_WIN32)
    return _mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

int main(void) {
    crimp_squashfs_entry_list list;
    if (crimp_squashfs_extract(FIXTURE_PATH, OUTPUT_DIR, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_squashfs_extract failed on %s\n", FIXTURE_PATH);
        return 1;
    }
    crimp_squashfs_entry_list_free(&list);

    int ok = 1;
    ok &= check_file("etc/config.txt", EXPECTED_CONFIG, sizeof(EXPECTED_CONFIG) - 1);
    ok &= check_file("etc/passwd", EXPECTED_PASSWD, sizeof(EXPECTED_PASSWD) - 1);
    ok &= check_file("bin/busybox", EXPECTED_BUSYBOX, sizeof(EXPECTED_BUSYBOX) - 1);
    ok &= check_file("bin/nested/deep.txt", EXPECTED_DEEP, sizeof(EXPECTED_DEEP) - 1);

    /* bigfile.bin: deterministic repeating "0123456789" pattern, 11000
     * bytes, built with a 4KiB block size so it spans two full data blocks
     * plus a fragment-packed tail - exercises block_sizes[] parsing and
     * the fragment table lookup in the same test. */
    unsigned char expected_big[BIGFILE_SIZE];
    for (size_t i = 0; i < BIGFILE_SIZE; i++) {
        expected_big[i] = (unsigned char)('0' + (i % 10));
    }
    ok &= check_file("bin/bigfile.bin", expected_big, BIGFILE_SIZE);

    /* bin/sh is a symlink in the fixture - milestone 2b only extracts
     * regular file content, so nothing should have been written for it. */
    char symlink_path[1024];
    snprintf(symlink_path, sizeof(symlink_path), "%s/bin/sh", OUTPUT_DIR);
    FILE *sh = fopen(symlink_path, "rb");
    if (sh) {
        fprintf(stderr, "FAIL: '%s' should not exist (symlink content isn't extracted)\n",
                symlink_path);
        fclose(sh);
        ok = 0;
    }

    if (!ok) {
        return 1;
    }

    /* A block that fails to decompress partway through extraction must not
     * leave a truncated file behind. */
    const char *corrupt_path = "test_fixture_squashfs_corrupt_block.img";
    if (build_corrupt_block_image(corrupt_path) != 0) {
        fprintf(stderr, "FAIL: could not build corrupt-block fixture\n");
        return 1;
    }
    const char *corrupt_out_dir = "squashfs_extract_corrupt_output";
    make_test_directory(corrupt_out_dir); /* ignore EEXIST - fine either way */
    crimp_squashfs_entry_list corrupt_list;
    int corrupt_rc = crimp_squashfs_extract(corrupt_path, corrupt_out_dir, &corrupt_list);
    if (corrupt_rc == 0) {
        fprintf(stderr, "FAIL: expected crimp_squashfs_extract to fail on a corrupt data block\n");
        crimp_squashfs_entry_list_free(&corrupt_list);
        return 1;
    }
    char corrupt_file_path[1024];
    snprintf(corrupt_file_path, sizeof(corrupt_file_path), "%s/corrupt.bin", corrupt_out_dir);
    FILE *leftover = fopen(corrupt_file_path, "rb");
    if (leftover) {
        fclose(leftover);
        fprintf(stderr,
                "FAIL: '%s' should have been removed after its decompression failed, not left "
                "as a truncated file\n",
                corrupt_file_path);
        return 1;
    }

    /* A stale regular file already occupying a path the walk needs to
     * create as a directory must not be silently treated as success - even
     * when (as here) the directory has no children whose own failure would
     * otherwise mask the collision. */
    const char *empty_dir_path = "test_fixture_squashfs_empty_dir_collision.img";
    if (build_empty_dir_image(empty_dir_path) != 0) {
        fprintf(stderr, "FAIL: could not build empty-dir-collision fixture\n");
        return 1;
    }
    const char *collision_out_dir = "squashfs_extract_collision_output";
    make_test_directory(collision_out_dir);
    char collision_bin_path[1024];
    snprintf(collision_bin_path, sizeof(collision_bin_path), "%s/emptydir", collision_out_dir);
    FILE *stale = fopen(collision_bin_path, "wb");
    if (!stale) {
        fprintf(stderr, "FAIL: could not create stale-file fixture at '%s'\n", collision_bin_path);
        return 1;
    }
    fputs("not a directory", stale);
    fclose(stale);
    crimp_squashfs_entry_list collision_list;
    int collision_rc = crimp_squashfs_extract(empty_dir_path, collision_out_dir, &collision_list);
    if (collision_rc == 0) {
        fprintf(stderr,
                "FAIL: expected crimp_squashfs_extract to fail when 'emptydir' already exists as "
                "a regular file, not a directory\n");
        crimp_squashfs_entry_list_free(&collision_list);
        return 1;
    }

    /* block_size below the spec minimum must be rejected up front. */
    const char *tiny_block_path = "test_fixture_squashfs_tiny_block_size.img";
    if (build_tiny_block_size_image(tiny_block_path) != 0) {
        fprintf(stderr, "FAIL: could not build tiny-block-size fixture\n");
        return 1;
    }
    const char *tiny_block_out_dir = "squashfs_extract_tiny_block_output";
    crimp_squashfs_entry_list tiny_block_list;
    if (crimp_squashfs_extract(tiny_block_path, tiny_block_out_dir, &tiny_block_list) == 0) {
        fprintf(stderr,
                "FAIL: expected crimp_squashfs_extract to reject a block_size below the spec "
                "minimum\n");
        crimp_squashfs_entry_list_free(&tiny_block_list);
        return 1;
    }

    /* A missing image file must be rejected at the initial fopen(). */
    crimp_squashfs_entry_list missing_list;
    if (crimp_squashfs_extract("test_fixture_squashfs_does_not_exist.img", "squashfs_extract_missing_output",
                                &missing_list) == 0) {
        fprintf(stderr, "FAIL: expected crimp_squashfs_extract to reject a missing image file\n");
        crimp_squashfs_entry_list_free(&missing_list);
        return 1;
    }

    /* output_dir itself colliding with a pre-existing regular file (as
     * opposed to a stale file deeper in the tree, already covered above)
     * must fail at make_directory(), not proceed as if it were created. */
    const char *output_collision_path = "squashfs_extract_output_is_a_file";
    FILE *stale_output = fopen(output_collision_path, "wb");
    if (!stale_output) {
        fprintf(stderr, "FAIL: could not create stale-output-dir fixture at '%s'\n",
                output_collision_path);
        return 1;
    }
    fputs("not a directory either", stale_output);
    fclose(stale_output);
    crimp_squashfs_entry_list output_collision_list;
    if (crimp_squashfs_extract(FIXTURE_PATH, output_collision_path, &output_collision_list) == 0) {
        fprintf(stderr,
                "FAIL: expected crimp_squashfs_extract to reject output_dir '%s' already "
                "existing as a regular file\n",
                output_collision_path);
        crimp_squashfs_entry_list_free(&output_collision_list);
        return 1;
    }

    /* A data block stored uncompressed (the other half of
     * read_and_inflate_block()'s branch - every other fixture here uses
     * gzip) must extract correctly. */
    const char *uncompressed_path = "test_fixture_squashfs_uncompressed_block.img";
    if (build_uncompressed_block_image(uncompressed_path) != 0) {
        fprintf(stderr, "FAIL: could not build uncompressed-block fixture\n");
        return 1;
    }
    const char *uncompressed_out_dir = "squashfs_extract_uncompressed_output";
    crimp_squashfs_entry_list uncompressed_list;
    if (crimp_squashfs_extract(uncompressed_path, uncompressed_out_dir, &uncompressed_list) != 0) {
        fprintf(stderr, "FAIL: crimp_squashfs_extract failed on an uncompressed-block image\n");
        return 1;
    }
    crimp_squashfs_entry_list_free(&uncompressed_list);
    unsigned char expected_raw[4096];
    for (size_t i = 0; i < sizeof(expected_raw); i++) {
        expected_raw[i] = (unsigned char)(i % 251);
    }
    char raw_path[1024];
    snprintf(raw_path, sizeof(raw_path), "%s/raw.bin", uncompressed_out_dir);
    size_t raw_len = 0;
    unsigned char *raw_buf = read_whole_file(raw_path, &raw_len);
    if (!raw_buf || raw_len != sizeof(expected_raw) ||
        memcmp(raw_buf, expected_raw, sizeof(expected_raw)) != 0) {
        fprintf(stderr, "FAIL: uncompressed block content mismatch in '%s'\n", raw_path);
        free(raw_buf);
        return 1;
    }
    free(raw_buf);

    printf("PASS: crimp_squashfs_extract content matches unsquashfs -d ground truth\n");
    return 0;
}
