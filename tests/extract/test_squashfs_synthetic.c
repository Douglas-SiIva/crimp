#include "extract_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hand-builds tiny, spec-compliant (uncompressed) SquashFS images to cover
 * inode-type branches and error paths the real-image fixture in
 * test_squashfs_list.c doesn't reach: extended directory/file/symlink
 * inodes (8/9/10), a misc inode type (fifo, exercises the "unhandled type"
 * default branch — real firmware has these for /dev nodes), a compressed
 * metadata block (unsupported until milestone 2 — must fail cleanly, not
 * misparse), and a truncated/corrupt file. See
 * .claude/skills/squashfs-extraction/SKILL.md for the field layout this
 * mirrors. */

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} bytebuf;

static void bb_init(bytebuf *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void bb_free(bytebuf *b) {
    free(b->data);
}

static void bb_append(bytebuf *b, const void *p, size_t n) {
    if (b->len + n > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 64;
        while (new_cap < b->len + n) {
            new_cap *= 2;
        }
        b->data = (uint8_t *)realloc(b->data, new_cap);
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void bb_u16(bytebuf *b, uint16_t v) { bb_append(b, &v, 2); }
static void bb_u32(bytebuf *b, uint32_t v) { bb_append(b, &v, 4); }
static void bb_u64(bytebuf *b, uint64_t v) { bb_append(b, &v, 8); }

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

/* Common 16-byte inode header shared by every type. */
static void write_inode_header(bytebuf *b, uint16_t type, uint32_t inode_number) {
    bb_u16(b, type);
    bb_u16(b, 0); /* permissions */
    bb_u16(b, 0); /* uid_idx */
    bb_u16(b, 0); /* gid_idx */
    bb_u32(b, 0); /* mtime */
    bb_u32(b, inode_number);
}

static void write_dir_entry(bytebuf *dir, uint16_t offset, uint16_t basic_type,
                             const char *name) {
    uint16_t name_len = (uint16_t)strlen(name);
    bb_u16(dir, offset);
    bb_u16(dir, 0); /* inode_offset delta — unused by the parser (random-access lookup) */
    bb_u16(dir, basic_type);
    bb_u16(dir, (uint16_t)(name_len - 1)); /* off-by-one encoded */
    bb_append(dir, name, name_len);
}

/* Builds a single-metadata-block-per-table image with:
 *   / (root, basic dir)
 *     ext_file   -> extended file inode (type 9), size 100
 *     ext_dir/   -> extended directory inode (type 8)
 *       dev      -> basic fifo inode (type 6) — hits the "other" default branch
 *     ext_link   -> extended symlink inode (type 10), target_size 5
 * and writes it to `path`. Returns 0 on success. */
static int build_extended_types_image(const char *path) {
    bytebuf inodes, dirs;
    bb_init(&inodes);
    bb_init(&dirs);

    /* Leaf inodes first (no forward references needed). */
    uint32_t fifo_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 6, 100); /* basic fifo — default branch, no extra fields read */

    uint32_t ext_file_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 9, 101); /* extended file */
    bb_u64(&inodes, 0);                  /* blocks_start */
    bb_u64(&inodes, 100);                /* file_size */
    bb_u64(&inodes, 0);                  /* sparse */
    bb_u32(&inodes, 1);                  /* link_count */
    bb_u32(&inodes, 0xFFFFFFFFu);        /* frag_index (none) */
    bb_u32(&inodes, 0);                  /* block_offset */
    bb_u32(&inodes, 0xFFFFFFFFu);        /* xattr_index (none) */

    uint32_t ext_link_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 10, 102); /* extended symlink */
    bb_u32(&inodes, 1);                   /* link_count */
    bb_u32(&inodes, 5);                   /* target_size */

    /* ext_dir's own listing (one entry: "dev" -> the fifo above), built
     * before ext_dir's inode so we know where it lives in `dirs`. */
    uint32_t ext_dir_listing_off = (uint32_t)dirs.len;
    bb_u32(&dirs, 0); /* count - 1 (one entry) */
    bb_u32(&dirs, 0); /* start: inode table block offset (single block, always 0) */
    bb_u32(&dirs, 0); /* inode_number base — unused by the parser */
    write_dir_entry(&dirs, (uint16_t)fifo_off, 6, "dev");
    uint32_t ext_dir_listing_len = (uint32_t)(dirs.len - ext_dir_listing_off);

    uint32_t ext_dir_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 8, 103); /* extended directory */
    bb_u32(&inodes, 1);                  /* link_count */
    bb_u32(&inodes, ext_dir_listing_len + 3); /* file_size (dir_size), +3 per spec */
    bb_u32(&inodes, 0);                  /* block_index (single dir block, always 0) */
    bb_u32(&inodes, 1);                  /* parent_inode */
    bb_u16(&inodes, 0);                  /* index_count */
    bb_u16(&inodes, (uint16_t)ext_dir_listing_off); /* block_offset */
    bb_u32(&inodes, 0xFFFFFFFFu);        /* xattr_index (none) */

    /* A genuinely empty directory (dir_size < 4 — no table entries at all,
     * common in real firmware for mount points like /proc or /tmp). */
    uint32_t empty_dir_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 1, 104);
    bb_u32(&inodes, 0); /* block_index — never read, dir_size short-circuits first */
    bb_u32(&inodes, 1); /* link_count */
    bb_u16(&inodes, 0); /* file_size = 0: empty directory */
    bb_u16(&inodes, 0); /* block_offset */
    bb_u32(&inodes, 1); /* parent_inode */

    /* Root directory's listing: ext_file, ext_dir, ext_link, empty_dir. */
    uint32_t root_listing_off = (uint32_t)dirs.len;
    bb_u32(&dirs, 3); /* count - 1 (four entries) */
    bb_u32(&dirs, 0); /* start */
    bb_u32(&dirs, 0); /* inode_number base */
    write_dir_entry(&dirs, (uint16_t)ext_file_off, 2, "ext_file");
    write_dir_entry(&dirs, (uint16_t)ext_dir_off, 1, "ext_dir");
    write_dir_entry(&dirs, (uint16_t)ext_link_off, 3, "ext_link");
    write_dir_entry(&dirs, (uint16_t)empty_dir_off, 1, "empty_dir");
    uint32_t root_listing_len = (uint32_t)(dirs.len - root_listing_off);

    uint32_t root_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 1, 1); /* basic root directory */
    bb_u32(&inodes, 0);                /* block_index */
    bb_u32(&inodes, 1);                /* link_count */
    bb_u16(&inodes, (uint16_t)(root_listing_len + 3)); /* file_size (dir_size) */
    bb_u16(&inodes, (uint16_t)root_listing_off);       /* block_offset */
    bb_u32(&inodes, 0);                                /* parent_inode */

    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.inodes = 5;
    sb.block_size = 131072;
    sb.block_log = 17;
    sb.s_major = 4;
    sb.compression = 1; /* gzip id, irrelevant here since blocks are stored uncompressed */
    sb.root_inode = ((uint64_t)0 << 16) | root_off;
    sb.inode_table_start = sizeof(test_superblock);
    sb.directory_table_start = sb.inode_table_start + 2 + inodes.len;
    sb.bytes_used = sb.directory_table_start + 2 + dirs.len;

    FILE *f = fopen(path, "wb");
    if (!f) {
        bb_free(&inodes);
        bb_free(&dirs);
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);
    uint16_t inode_hdr = (uint16_t)(inodes.len | 0x8000); /* uncompressed */
    fwrite(&inode_hdr, sizeof(inode_hdr), 1, f);
    fwrite(inodes.data, 1, inodes.len, f);
    uint16_t dir_hdr = (uint16_t)(dirs.len | 0x8000);
    fwrite(&dir_hdr, sizeof(dir_hdr), 1, f);
    fwrite(dirs.data, 1, dirs.len, f);
    fclose(f);

    bb_free(&inodes);
    bb_free(&dirs);
    return 0;
}

/* A valid-looking superblock whose inode table's first metadata block is
 * marked *compressed* (MSB clear) — must be rejected cleanly, not misread
 * as garbage-but-successful. */
static int build_compressed_block_image(const char *path) {
    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.inodes = 1;
    sb.block_size = 131072;
    sb.block_log = 17;
    sb.s_major = 4;
    sb.root_inode = 0;
    sb.inode_table_start = sizeof(test_superblock);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);
    uint16_t compressed_hdr = 16; /* MSB clear = compressed; payload is fake/irrelevant */
    fwrite(&compressed_hdr, sizeof(compressed_hdr), 1, f);
    uint8_t fake_payload[16] = {0};
    fwrite(fake_payload, 1, sizeof(fake_payload), f);
    fclose(f);
    return 0;
}

/* A file that ends right after a valid-looking superblock — reading the
 * root inode has to reach past EOF for its metadata block header. */
static int build_truncated_after_superblock_image(const char *path) {
    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.block_size = 131072;
    sb.block_log = 17;
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

/* A metadata block header claiming an on-disk size bigger than the 8KiB
 * buffer a decompressed block can ever hold — must be rejected, not
 * overflow anything. */
static int build_oversized_block_image(const char *path) {
    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.block_size = 131072;
    sb.block_log = 17;
    sb.s_major = 4;
    sb.root_inode = 0;
    sb.inode_table_start = sizeof(test_superblock);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);
    uint16_t hdr = (uint16_t)(9000 | 0x8000); /* 9000 > METADATA_BLOCK_SIZE, uncompressed */
    fwrite(&hdr, sizeof(hdr), 1, f);
    fclose(f);
    return 0;
}

/* A metadata block header that promises more bytes than the file actually
 * has left — the block body itself is truncated. */
static int build_short_block_body_image(const char *path) {
    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.block_size = 131072;
    sb.block_log = 17;
    sb.s_major = 4;
    sb.root_inode = 0;
    sb.inode_table_start = sizeof(test_superblock);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);
    uint16_t hdr = (uint16_t)(100 | 0x8000); /* promises 100 bytes, uncompressed */
    fwrite(&hdr, sizeof(hdr), 1, f);
    uint8_t only_ten[10] = {0};
    fwrite(only_ten, 1, sizeof(only_ten), f); /* only 10 of the promised 100 */
    fclose(f);
    return 0;
}

/* A directory whose own dir_size field is internally inconsistent (too
 * small to even hold one header) — nested one level down, so this also
 * exercises the recursive-failure-propagates-up path in walk_directory and
 * crimp_squashfs_list's own post-root-inode failure branch, neither of
 * which the other fixtures reach (they fail earlier, at the root inode
 * lookup itself). */
static int build_bad_dir_size_image(const char *path) {
    bytebuf inodes, dirs;
    bb_init(&inodes);
    bb_init(&dirs);

    uint32_t baddir_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 1, 2); /* basic directory, "baddir" */
    bb_u32(&inodes, 0);                /* block_index */
    bb_u32(&inodes, 1);                /* link_count */
    bb_u16(&inodes, 8);                /* file_size: remaining = 8-3 = 5, < 12 */
    bb_u16(&inodes, 0);                /* block_offset */
    bb_u32(&inodes, 1);                /* parent_inode */

    uint32_t root_listing_off = (uint32_t)dirs.len;
    bb_u32(&dirs, 0); /* one entry */
    bb_u32(&dirs, 0);
    bb_u32(&dirs, 0);
    write_dir_entry(&dirs, (uint16_t)baddir_off, 1, "baddir");
    uint32_t root_listing_len = (uint32_t)(dirs.len - root_listing_off);

    uint32_t root_off = (uint32_t)inodes.len;
    write_inode_header(&inodes, 1, 1);
    bb_u32(&inodes, 0);
    bb_u32(&inodes, 1);
    bb_u16(&inodes, (uint16_t)(root_listing_len + 3));
    bb_u16(&inodes, (uint16_t)root_listing_off);
    bb_u32(&inodes, 0);

    test_superblock sb;
    memset(&sb, 0, sizeof(sb));
    memcpy(&sb.magic, "hsqs", 4);
    sb.block_size = 131072;
    sb.block_log = 17;
    sb.s_major = 4;
    sb.root_inode = ((uint64_t)0 << 16) | root_off;
    sb.inode_table_start = sizeof(test_superblock);
    sb.directory_table_start = sb.inode_table_start + 2 + inodes.len;

    FILE *f = fopen(path, "wb");
    if (!f) {
        bb_free(&inodes);
        bb_free(&dirs);
        return -1;
    }
    fwrite(&sb, sizeof(sb), 1, f);
    uint16_t inode_hdr = (uint16_t)(inodes.len | 0x8000);
    fwrite(&inode_hdr, sizeof(inode_hdr), 1, f);
    fwrite(inodes.data, 1, inodes.len, f);
    uint16_t dir_hdr = (uint16_t)(dirs.len | 0x8000);
    fwrite(&dir_hdr, sizeof(dir_hdr), 1, f);
    fwrite(dirs.data, 1, dirs.len, f);
    fclose(f);

    bb_free(&inodes);
    bb_free(&dirs);
    return 0;
}

static int expect_list_fails(const char *label, int (*builder)(const char *), const char *path) {
    if (builder(path) != 0) {
        fprintf(stderr, "FAIL: could not build %s fixture\n", label);
        return 1;
    }
    crimp_squashfs_entry_list list;
    if (crimp_squashfs_list(path, &list) == 0) {
        fprintf(stderr, "FAIL: expected crimp_squashfs_list to reject %s\n", label);
        crimp_squashfs_entry_list_free(&list);
        return 1;
    }
    return 0;
}

int main(void) {
    const char *extended_path = "test_fixture_squashfs_extended.img";
    if (build_extended_types_image(extended_path) != 0) {
        fprintf(stderr, "FAIL: could not build extended-types fixture\n");
        return 1;
    }

    crimp_squashfs_entry_list list;
    if (crimp_squashfs_list(extended_path, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_squashfs_list rejected a well-formed extended-types image\n");
        return 1;
    }

    int saw_ext_file = 0, saw_ext_dir = 0, saw_ext_link = 0, saw_dev = 0, saw_empty_dir = 0;
    for (size_t i = 0; i < list.count; i++) {
        crimp_squashfs_entry *e = &list.items[i];
        if (strcmp(e->path, "ext_file") == 0 && !e->is_dir && e->size == 100) saw_ext_file = 1;
        if (strcmp(e->path, "ext_dir") == 0 && e->is_dir) saw_ext_dir = 1;
        if (strcmp(e->path, "ext_link") == 0 && !e->is_dir && e->size == 5) saw_ext_link = 1;
        if (strcmp(e->path, "ext_dir/dev") == 0 && !e->is_dir) saw_dev = 1;
        if (strcmp(e->path, "empty_dir") == 0 && e->is_dir) saw_empty_dir = 1;
    }
    crimp_squashfs_entry_list_free(&list);

    if (!saw_ext_file || !saw_ext_dir || !saw_ext_link || !saw_dev || !saw_empty_dir) {
        fprintf(stderr,
                "FAIL: expected ext_file(size=100)/ext_dir/ext_link(size=5)/ext_dir/dev/empty_dir, "
                "got ext_file=%d ext_dir=%d ext_link=%d dev=%d empty_dir=%d\n",
                saw_ext_file, saw_ext_dir, saw_ext_link, saw_dev, saw_empty_dir);
        return 1;
    }

    /* Compressed metadata block: must fail, not misparse. */
    const char *compressed_path = "test_fixture_squashfs_compressed.img";
    if (build_compressed_block_image(compressed_path) != 0) {
        fprintf(stderr, "FAIL: could not build compressed-block fixture\n");
        return 1;
    }
    crimp_squashfs_entry_list compressed_list;
    if (crimp_squashfs_list(compressed_path, &compressed_list) == 0) {
        fprintf(stderr, "FAIL: expected crimp_squashfs_list to reject a compressed metadata block\n");
        crimp_squashfs_entry_list_free(&compressed_list);
        return 1;
    }

    /* Truncated/corrupt file: too short to even hold a superblock. */
    const char *truncated_path = "test_fixture_squashfs_truncated.img";
    FILE *tf = fopen(truncated_path, "wb");
    if (!tf) {
        fprintf(stderr, "FAIL: could not create truncated fixture\n");
        return 1;
    }
    fputs("hsqs", tf); /* magic only, nowhere near a full superblock */
    fclose(tf);
    crimp_squashfs_entry_list truncated_list;
    if (crimp_squashfs_list(truncated_path, &truncated_list) == 0) {
        fprintf(stderr, "FAIL: expected crimp_squashfs_list to reject a truncated file\n");
        crimp_squashfs_entry_list_free(&truncated_list);
        return 1;
    }

    /* Missing file entirely. */
    crimp_squashfs_entry_list missing_list;
    if (crimp_squashfs_list("test_fixture_squashfs_does_not_exist.img", &missing_list) == 0) {
        fprintf(stderr, "FAIL: expected crimp_squashfs_list to reject a missing file\n");
        crimp_squashfs_entry_list_free(&missing_list);
        return 1;
    }

    int failures = 0;
    failures += expect_list_fails("a file truncated right after the superblock",
                                   build_truncated_after_superblock_image,
                                   "test_fixture_squashfs_trunc_sb.img");
    failures += expect_list_fails("an oversized metadata block size", build_oversized_block_image,
                                   "test_fixture_squashfs_oversized.img");
    failures += expect_list_fails("a metadata block body shorter than its header promises",
                                   build_short_block_body_image,
                                   "test_fixture_squashfs_short_body.img");
    failures += expect_list_fails("a directory with an internally inconsistent dir_size",
                                   build_bad_dir_size_image, "test_fixture_squashfs_baddir.img");
    if (failures > 0) {
        return 1;
    }

    printf("PASS: extended inode types, misc types, and error paths all behave correctly\n");
    return 0;
}
