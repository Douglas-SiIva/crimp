#include "extract_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Regression coverage for cramfs's one real trap squashfs never had: on-disk
 * byte order isn't fixed (see .claude/skills/cramfs-extraction/SKILL.md).
 * No big-endian-host tool is conveniently available in this project's dev
 * environment to generate a real big-endian image (unlike the little-endian
 * fixtures, built with real mkfs.cramfs), so this hand-builds a small,
 * deliberately big-endian image byte-by-byte instead - every multi-byte
 * field written in big-endian order, confirmed by using a "hole" (all-zero,
 * sparse) file so the block-pointer decode path is exercised without also
 * needing a real zlib-compressed payload (which would require linking zlib
 * into this test just to construct the fixture). */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t size;
    uint32_t flags;
    uint32_t future;
    uint8_t signature[16];
    uint32_t fsid_crc;
    uint32_t fsid_edition;
    uint32_t fsid_blocks;
    uint32_t fsid_files;
    uint8_t name[16];
} test_super_head; /* everything up to (not including) the root inode - 64 bytes */
#pragma pack(pop)

#define CRAMFS_MAGIC 0x28cd3d45u
#define SUPER_SIZE 76 /* super head (64) + root inode (12) */

static void fw32_be(FILE *f, uint32_t v) {
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    fwrite(b, 1, 4, f);
}

/* Packs mode/uid/size/gid/namelen/offset into the three big-endian on-disk
 * words, matching cramfs's inode bitfield layout (see SKILL.md). */
static void write_inode_be(FILE *f, uint32_t mode, uint32_t uid, uint32_t size, uint32_t gid,
                            uint32_t namelen_words, uint32_t offset_words) {
    fw32_be(f, (uid << 16) | (mode & 0xFFFFu));
    fw32_be(f, ((gid & 0xFFu) << 24) | (size & 0xFFFFFFu));
    fw32_be(f, ((offset_words & 0x3FFFFFFu) << 6) | (namelen_words & 0x3Fu));
}

#define S_IFDIR_ 0x4000u
#define S_IFREG_ 0x8000u

/* Builds a minimal valid big-endian cramfs image: root directory containing
 * one regular file "f.bin", 100 bytes, entirely a "hole" (zero-filled, no
 * compressed data on disk at all - see SKILL.md's block-pointer layout).
 * Layout: superblock (0-75), root's one directory entry (76-95: 12-byte
 * inode + "f.bin\0\0\0" padded to 8 bytes), f.bin's one-entry block-pointer
 * array (96-99). */
static int build_be_image(const char *path) {
    const char name[] = "f.bin";
    const uint32_t namelen_bytes = 8; /* "f.bin" (5) padded to a 4-byte-aligned 8 */
    const uint32_t root_entries_size = 12 + namelen_bytes; /* = 20 */
    const uint32_t root_entries_offset = SUPER_SIZE;        /* = 76 */
    const uint32_t fbin_ptr_array_offset = root_entries_offset + root_entries_size; /* = 96 */
    const uint32_t file_size = 100;
    const uint32_t nblocks = 1;
    const uint32_t data_start = fbin_ptr_array_offset + 4 * nblocks; /* = 100 */
    const uint32_t image_size = data_start;                          /* nothing after: pure hole */

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }

    fw32_be(f, CRAMFS_MAGIC);
    fw32_be(f, image_size);
    fw32_be(f, 0); /* flags */
    fw32_be(f, 0); /* future */
    fwrite("Compressed ROMFS", 1, 16, f); /* signature - raw bytes, not endianness-sensitive */
    fw32_be(f, 0); /* fsid.crc */
    fw32_be(f, 0); /* fsid.edition */
    fw32_be(f, 1); /* fsid.blocks */
    fw32_be(f, 1); /* fsid.files */
    uint8_t zero16[16];
    memset(zero16, 0, sizeof(zero16));
    fwrite(zero16, 1, sizeof(zero16), f); /* name */

    /* root inode: dir, size = root_entries_size, offset (words) points at
     * root_entries_offset. */
    write_inode_be(f, S_IFDIR_ | 0755, 0, root_entries_size, 0, 0, root_entries_offset >> 2);

    /* f.bin's directory entry: regular file, size = file_size, offset
     * (words) points at its block-pointer array. */
    write_inode_be(f, S_IFREG_ | 0644, 0, file_size, 0, (uint32_t)(sizeof(name) - 1 + 3) >> 2,
                    fbin_ptr_array_offset >> 2);
    fwrite(name, 1, sizeof(name) - 1, f);
    uint8_t namepad[3] = {0, 0, 0};
    fwrite(namepad, 1, namelen_bytes - (sizeof(name) - 1), f);

    /* f.bin's block-pointer array: one entry equal to data_start itself -
     * zero-length compressed range, i.e. a hole. */
    fw32_be(f, data_start);

    fclose(f);
    return 0;
}

int main(void) {
    const char *path = "test_fixture_cramfs_be.img";
    if (build_be_image(path) != 0) {
        fprintf(stderr, "FAIL: could not build big-endian fixture\n");
        return 1;
    }

    crimp_fs_info info;
    if (crimp_cramfs_identify(path, &info) != 0) {
        fprintf(stderr, "FAIL: crimp_cramfs_identify failed on a valid big-endian image\n");
        return 1;
    }
    if (info.type != CRIMP_FS_CRAMFS) {
        fprintf(stderr, "FAIL: expected CRIMP_FS_CRAMFS\n");
        return 1;
    }

    crimp_fs_entry_list list;
    if (crimp_cramfs_list(path, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_cramfs_list failed on a valid big-endian image\n");
        return 1;
    }
    if (list.count != 1 || strcmp(list.items[0].path, "f.bin") != 0 || list.items[0].is_dir ||
        list.items[0].size != 100) {
        fprintf(stderr, "FAIL: unexpected listing (count=%zu)\n", list.count);
        crimp_fs_entry_list_free(&list);
        return 1;
    }
    crimp_fs_entry_list_free(&list);

    const char *out_dir = "cramfs_be_output";
    crimp_fs_entry_list extract_list;
    if (crimp_cramfs_extract(path, out_dir, &extract_list) != 0) {
        fprintf(stderr, "FAIL: crimp_cramfs_extract failed on a valid big-endian image\n");
        return 1;
    }
    crimp_fs_entry_list_free(&extract_list);

    char extracted_path[512];
    snprintf(extracted_path, sizeof(extracted_path), "%s/f.bin", out_dir);
    FILE *ef = fopen(extracted_path, "rb");
    if (!ef) {
        fprintf(stderr, "FAIL: '%s' was not extracted\n", extracted_path);
        return 1;
    }
    unsigned char buf[128];
    size_t n = fread(buf, 1, sizeof(buf), ef);
    fclose(ef);
    if (n != 100) {
        fprintf(stderr, "FAIL: expected 100 bytes, got %zu\n", n);
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        if (buf[i] != 0) {
            fprintf(stderr, "FAIL: expected all-zero hole content, byte %zu was 0x%02x\n", i,
                    buf[i]);
            return 1;
        }
    }

    printf("PASS: crimp_cramfs_identify/list/extract correctly decode a big-endian image\n");
    return 0;
}
