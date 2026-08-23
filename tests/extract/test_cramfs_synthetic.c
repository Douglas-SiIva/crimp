#include "extract_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Regression tests for two real findings from /code-review high on the
 * cramfs work: (1) a directory's offset/size wasn't checked against the
 * superblock's declared whole-image size before being walked, and (2)
 * crimp_fs_path_component_is_safe() (fs_util.c, shared with squashfs.c)
 * didn't reject a zero-length name itself, relying on every caller to
 * guard against it independently - the exact class of mistake that caused
 * a real, previously-shipped critical path-traversal bug in this codebase
 * (PR #33). Both fixes verified to actually matter by reverting each one
 * temporarily and confirming the corresponding case here fails. */

#define CRAMFS_MAGIC 0x28cd3d45u
#define SUPER_SIZE 76

static void fw32_le(FILE *f, uint32_t v) { fwrite(&v, sizeof(v), 1, f); }

static void write_inode_le(FILE *f, uint32_t mode, uint32_t uid, uint32_t size, uint32_t gid,
                            uint32_t namelen_words, uint32_t offset_words) {
    fw32_le(f, (uid << 16) | (mode & 0xFFFFu));
    fw32_le(f, ((gid & 0xFFu) << 24) | (size & 0xFFFFFFu));
    fw32_le(f, ((offset_words & 0x3FFFFFFu) << 6) | (namelen_words & 0x3Fu));
}

#define S_IFDIR_ 0x4000u

static void write_superblock(FILE *f, uint32_t image_size, uint32_t root_size,
                              uint32_t root_offset) {
    fw32_le(f, CRAMFS_MAGIC);
    fw32_le(f, image_size);
    fw32_le(f, 0);
    fw32_le(f, 0);
    fwrite("Compressed ROMFS", 1, 16, f);
    fw32_le(f, 0);
    fw32_le(f, 0);
    fw32_le(f, 1);
    fw32_le(f, 0);
    uint8_t zero16[16];
    memset(zero16, 0, sizeof(zero16));
    fwrite(zero16, 1, sizeof(zero16), f);
    write_inode_le(f, S_IFDIR_ | 0755, 0, root_size, 0, 0, root_offset >> 2);
}

/* A root directory whose offset points past the superblock's own declared
 * `size` - the physical file still has real bytes there (this test writes
 * some), but a crafted image could have anything at all past its declared
 * boundary. Must be rejected, not walked as if it were legitimate. */
static int build_offset_past_declared_size(const char *path) {
    const uint32_t declared_size = SUPER_SIZE; /* claims nothing exists past the superblock */
    const uint32_t root_offset = SUPER_SIZE + 1000; /* well past declared_size */
    /* Exactly one entry's worth (12-byte inode + 4-byte name) - a size
     * mismatch here would make the entry-count bookkeeping itself reject
     * the image for an unrelated reason, masking whether the offset-bounds
     * check is what's actually being tested. */
    const uint32_t root_entries_size = 16;

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    write_superblock(f, declared_size, root_entries_size, root_offset);
    /* Pad the physical file out to root_offset + root_entries_size with
     * zeros, then write a real-looking (but out of declared bounds) entry -
     * proves the physical bytes existing isn't what should matter. */
    for (uint32_t i = SUPER_SIZE; i < root_offset; i++) {
        fputc(0, f);
    }
    write_inode_le(f, 0x8000u | 0644, 0, 4, 0, 1, (root_offset + 32) >> 2);
    fwrite("x\0\0\0", 1, 4, f);
    fclose(f);
    return 0;
}

/* A directory entry whose name is entirely NUL padding (namelen=4 on disk,
 * every byte 0x00) - real_len trims to 0. Exercises
 * crimp_fs_path_component_is_safe()'s own zero-length rejection via
 * cramfs.c's real call path (cramfs.c itself no longer special-cases this,
 * per the code-review fix removing the now-redundant local check). */
static int build_zero_length_name(const char *path) {
    const uint32_t root_entries_size = 16; /* one entry: 12-byte inode + 4 bytes of name */
    const uint32_t root_offset = SUPER_SIZE;
    const uint32_t image_size = SUPER_SIZE + root_entries_size;

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    write_superblock(f, image_size, root_entries_size, root_offset);
    /* The one entry: a regular file whose namelen (1 word = 4 bytes) is
     * real, but every name byte is 0x00. */
    write_inode_le(f, 0x8000u | 0644, 0, 0, 0, 1, 0);
    uint8_t all_nul[4] = {0, 0, 0, 0};
    fwrite(all_nul, 1, sizeof(all_nul), f);
    fclose(f);
    return 0;
}

int main(void) {
    const char *p1 = "test_fixture_cramfs_offset_oob.img";
    if (build_offset_past_declared_size(p1) != 0) {
        fprintf(stderr, "FAIL: could not build offset-past-declared-size fixture\n");
        return 1;
    }
    crimp_fs_entry_list list1;
    if (crimp_cramfs_list(p1, &list1) == 0) {
        fprintf(stderr,
                "FAIL: expected crimp_cramfs_list to reject a root offset past the "
                "superblock's declared size\n");
        crimp_fs_entry_list_free(&list1);
        return 1;
    }

    const char *p2 = "test_fixture_cramfs_zero_name.img";
    if (build_zero_length_name(p2) != 0) {
        fprintf(stderr, "FAIL: could not build zero-length-name fixture\n");
        return 1;
    }
    crimp_fs_entry_list list2;
    if (crimp_cramfs_list(p2, &list2) == 0) {
        fprintf(stderr, "FAIL: expected crimp_cramfs_list to reject a zero-length entry name\n");
        crimp_fs_entry_list_free(&list2);
        return 1;
    }

    printf("PASS: cramfs rejects an out-of-declared-bounds directory offset and a "
           "zero-length entry name\n");
    return 0;
}
