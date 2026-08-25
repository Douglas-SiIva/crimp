#include "extract_internal.h"
#include "fs_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* cramfs (issue #9). See .claude/skills/cramfs-extraction/SKILL.md for the
 * full field-by-field spec and how it was derived/validated (cross-checked
 * against util-linux's disk-utils/{cramfs.h,cramfs_common.c,fsck.cramfs.c}
 * - the same tool used as ground truth below - plus confirmed empirically
 * against a real mkfs.cramfs image's raw bytes; an initial AI-summarized
 * read of the kernel driver got a real structural detail wrong, worth
 * knowing before trusting any single source on this format again).
 *
 * The one thing squashfs.c never had to deal with: on-disk byte order isn't
 * fixed. A cramfs image built on a big-endian host is genuinely big-endian
 * on disk. Every multi-byte read below goes through crimp_fs_decode_u32(), which
 * takes the image's detected endianness explicitly - never assume host
 * order the way squashfs.c's #pragma-packed struct + plain fread() does
 * (safe there only because squashfs is always little-endian regardless of
 * build host, and this project only targets little-endian hosts). */

#define CRAMFS_MAGIC 0x28cd3d45u
#define CRAMFS_SUPER_SIZE 76 /* magic+size+flags+future(16) + signature(16) + fsid(16) + name(16) + root inode(12) - confirmed against a real image's raw bytes, not just the header's field list */
#define CRAMFS_ROOT_INODE_OFFSET 64

/* Not stored in the superblock - an out-of-band convention. util-linux's
 * own tools default to getpagesize() (4096 on every platform this project
 * targets); treat that as fixed rather than speculatively supporting a
 * configurable block size with nothing real to validate it against. */
#define CRAMFS_BLOCK_SIZE 4096u

#define CRAMFS_S_IFMT 0xF000u
#define CRAMFS_S_IFDIR 0x4000u
#define CRAMFS_S_IFREG 0x8000u

typedef struct {
    uint32_t mode;
    uint32_t uid;
    uint32_t size;    /* directory: total bytes of entries; file/symlink: content length */
    uint32_t gid;
    uint32_t namelen; /* already in bytes (on-disk field is a word count) */
    uint64_t offset;  /* already in bytes (on-disk field is a word count); directory: first
                        * entry's position; file/symlink: block-pointer array's position */
} cramfs_inode;

/* Manual bit-level decode, not a C bitfield struct overlay - bitfield
 * packing order is compiler/ABI-defined, and this project's established
 * discipline (see squashfs.c) is to never trust that for on-disk format
 * parsing. Field boundaries confirmed against a real mkfs.cramfs image's
 * raw bytes (see SKILL.md) - mode/uid in word0, size/gid in word1,
 * namelen(6 bits)/offset(26 bits) in word2. */
static void decode_inode(const uint8_t *raw12, int big_endian, cramfs_inode *out) {
    uint32_t w0 = crimp_fs_decode_u32(raw12 + 0, big_endian);
    uint32_t w1 = crimp_fs_decode_u32(raw12 + 4, big_endian);
    uint32_t w2 = crimp_fs_decode_u32(raw12 + 8, big_endian);
    out->mode = w0 & 0xFFFFu;
    out->uid = (w0 >> 16) & 0xFFFFu;
    out->size = w1 & 0xFFFFFFu;
    out->gid = (w1 >> 24) & 0xFFu;
    out->namelen = (w2 & 0x3Fu) << 2;
    out->offset = (uint64_t)((w2 >> 6) & 0x3FFFFFFu) << 2;
}

typedef struct {
    uint32_t size;   /* whole-image byte bound, from the superblock - every offset used below
                       * must stay within this, same discipline as squashfs's bytes_used */
    int big_endian;
    cramfs_inode root;
} cramfs_super;

static int read_superblock(FILE *f, cramfs_super *sb) {
    uint8_t raw[CRAMFS_SUPER_SIZE];
    if (fseek(f, 0, SEEK_SET) != 0) {
        return -1;
    }
    if (fread(raw, 1, sizeof(raw), f) != sizeof(raw)) {
        return -1;
    }

    /* Endianness detection: the magic matches in exactly one byte order for
     * a genuine image (or neither, for a non-cramfs file) - util-linux's
     * fsck.cramfs rejects a mismatch outright rather than guessing, same
     * posture applied here. */
    int big_endian;
    if (crimp_fs_decode_u32(raw, 0) == CRAMFS_MAGIC) {
        big_endian = 0;
    } else if (crimp_fs_decode_u32(raw, 1) == CRAMFS_MAGIC) {
        big_endian = 1;
    } else {
        return -1;
    }

    sb->size = crimp_fs_decode_u32(raw + 4, big_endian);
    sb->big_endian = big_endian;
    decode_inode(raw + CRAMFS_ROOT_INODE_OFFSET, big_endian, &sb->root);

    /* The declared whole-image size must cover at least the superblock and
     * the root inode's own claimed entries region - anything smaller is
     * definitely malformed, reject before it can cause any offset computed
     * from it to look spuriously "in bounds" against too-small a size. */
    if (sb->size < CRAMFS_SUPER_SIZE) {
        return -1;
    }
    return 0;
}

int crimp_cramfs_identify(const char *path, crimp_fs_info *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    cramfs_super sb;
    int rc = read_superblock(f, &sb);
    fclose(f);
    if (rc != 0) {
        return -1;
    }

    out->type = CRIMP_FS_CRAMFS;
    out->inode_count = 0; /* cramfs doesn't store a total inode count anywhere in the
                            * superblock (fsid.files counts regular files only, not
                            * directories/symlinks/etc - not the same thing) */
    out->block_size = CRAMFS_BLOCK_SIZE;
    out->compression = 0; /* cramfs has no compressor-selection field - always zlib */
    out->bytes_used = sb.size;
    return 0;
}

const char *crimp_cramfs_compression_name(void) { return "zlib"; }

typedef struct {
    FILE *f;
    const cramfs_super *sb;
    crimp_fs_entry_list *out;
    const char *output_dir; /* NULL for crimp_cramfs_list (listing only, no writes) */
} cramfs_walk_context;

static int walk_directory(cramfs_walk_context *ctx, uint64_t offset, uint32_t size,
                           const char *parent_path, int depth);

/* Extracts one regular file's content to `disk_path`: the block-pointer
 * array at inode->offset gives, for each of ceil(size/BLOCK_SIZE) blocks,
 * the cumulative *end* byte-offset (from the start of the image) of that
 * block's compressed data - block N's compressed range is
 * [prev_end, pointer[N]), where prev_end is pointer[N-1] for N>0 or the
 * position right after the whole pointer array for N=0. A pointer equal to
 * prev_end means a "hole" (zero-filled block, no bytes on disk) - same
 * concept as squashfs's sparse blocks. Confirmed against util-linux's
 * fsck.cramfs.c (do_uncompress) - see SKILL.md. */
/* `disk_path` reaching every fopen()/remove() below has already been through
 * crimp_fs_path_component_is_safe() + crimp_fs_join_output_path() in
 * process_dir_entry() - the real sanitization, validated against
 * deliberately crafted traversal images (see fixture READMEs). SonarCloud's
 * c:S2083 (BETA path-injection taint rule) doesn't recognize that as a
 * taint-clearing boundary and flags every use downstream as a "leak" -
 * false positive, same class already documented in squashfs.c/fs_util.c. */
/* Reads the next block pointer at `*ptr_pos` (advancing it by 4) and
 * validates it against `prev_end`/`sb->size` - a crafted image could set a
 * decreasing/out-of-bounds pointer, which must be rejected before ever
 * computing a length via subtraction (that would otherwise underflow to a
 * huge unsigned value). Returns 1 and fills `*next_out` on success, 0 on
 * any read/validation failure. */
static int read_block_pointer(FILE *f, const cramfs_super *sb, uint64_t *ptr_pos,
                               uint64_t prev_end, uint32_t *next_out) {
    uint8_t ptr_raw[4];
    if (crimp_fs_seek64(f, *ptr_pos) != 0 || fread(ptr_raw, 1, 4, f) != 4) {
        return 0;
    }
    uint32_t next = crimp_fs_decode_u32(ptr_raw, sb->big_endian);
    *ptr_pos += 4;
    if (next < prev_end || next > sb->size) {
        return 0;
    }
    *next_out = next;
    return 1;
}

/* Fills `block_buf` (CRAMFS_BLOCK_SIZE bytes) with the block spanning
 * [prev_end, next) - a zero-filled "hole" if the span is empty, or the
 * zlib-decompressed span otherwise. `*comp_buf`/`*comp_cap` are a
 * caller-owned scratch buffer, grown (never shrunk) as needed across
 * calls. Returns 1 on success, 0 on any read/decompression failure or
 * size mismatch. */
static int fetch_block(FILE *f, uint8_t *block_buf, uint32_t expected_len, uint64_t prev_end,
                        uint32_t next, uint8_t **comp_buf, size_t *comp_cap) {
    uint64_t comp_len = next - prev_end;
    if (comp_len == 0) {
        memset(block_buf, 0, expected_len); /* hole */
        return 1;
    }
    if (comp_len > *comp_cap) {
        uint8_t *grown = (uint8_t *)realloc(*comp_buf, comp_len);
        if (!grown) {
            return 0;
        }
        *comp_buf = grown;
        *comp_cap = comp_len;
    }
    uLongf out_len = CRAMFS_BLOCK_SIZE;
    if (crimp_fs_seek64(f, prev_end) != 0 ||
        fread(*comp_buf, 1, (size_t)comp_len, f) != (size_t)comp_len ||
        uncompress(block_buf, &out_len, *comp_buf, (uLong)comp_len) != Z_OK ||
        out_len != expected_len) {
        return 0;
    }
    return 1;
}

static int extract_regular_file(FILE *f, const cramfs_super *sb, const cramfs_inode *inode,
                                 const char *disk_path) {
    if (crimp_fs_path_is_symlink(disk_path)) {
        return -1;
    }
    FILE *out = fopen(disk_path, "wb"); // NOSONAR
    if (!out) {
        return -1;
    }

    /* inode->size is a 24-bit on-disk field (max 16MiB-1) - nblocks is
     * inherently bounded, no MAX_BLOCKS_PER_FILE-style cap needed the way
     * squashfs's 64-bit size field required one. */
    uint32_t nblocks = (inode->size + CRAMFS_BLOCK_SIZE - 1) / CRAMFS_BLOCK_SIZE;

    uint8_t *block_buf = (uint8_t *)malloc(CRAMFS_BLOCK_SIZE);
    if (!block_buf) {
        fclose(out);
        remove(disk_path); // NOSONAR
        return -1;
    }

    uint8_t *comp_buf = NULL;
    size_t comp_cap = 0;
    int ok = 1;
    uint64_t ptr_pos = inode->offset;
    uint64_t prev_end = inode->offset + 4ULL * nblocks;
    uint64_t bytes_written = 0;

    uint32_t i = 0;
    while (ok && i < nblocks) {
        i++;
        uint32_t next;
        if (!read_block_pointer(f, sb, &ptr_pos, prev_end, &next)) {
            ok = 0;
            continue;
        }

        uint32_t expected_len = CRAMFS_BLOCK_SIZE;
        if (bytes_written + expected_len > inode->size) {
            expected_len = (uint32_t)(inode->size - bytes_written);
        }

        if (!fetch_block(f, block_buf, expected_len, prev_end, next, &comp_buf, &comp_cap) ||
            fwrite(block_buf, 1, expected_len, out) != expected_len) {
            ok = 0;
            continue;
        }
        bytes_written += expected_len;
        prev_end = next;
    }

    free(comp_buf);
    free(block_buf);
    fclose(out);
    if (!ok) {
        /* Don't leave a truncated file behind - same discipline as
         * squashfs's extract_regular_file. */
        remove(disk_path); // NOSONAR - see the c:S2083 note on this function's signature
        return -1;
    }
    return 0;
}

/* Reads one directory-table entry (a 12-byte inode immediately followed by
 * `namelen` name bytes, NUL-padded by the encoder to a 4-byte boundary),
 * resolves it, records it, and recurses into it if it's a directory.
 * Advances `*pos`/`*remaining` past this entry either way. */
static int process_dir_entry(cramfs_walk_context *ctx, uint64_t *pos, uint32_t *remaining,
                              const char *parent_path, int depth) {
    if (*remaining < 12) {
        return -1;
    }
    uint8_t raw[12];
    if (crimp_fs_seek64(ctx->f, *pos) != 0 || fread(raw, 1, 12, ctx->f) != 12) {
        return -1;
    }
    cramfs_inode child;
    decode_inode(raw, ctx->sb->big_endian, &child);
    *pos += 12;
    *remaining -= 12;

    /* namelen is a 6-bit on-disk field (<<2 already applied) - max 252
     * bytes, inherently bounded, unlike squashfs's 16-bit name field. Still
     * reject 0 (every real entry has a non-empty name) and anything larger
     * than what's left in this directory's declared entries region (before
     * subtracting, to avoid an unsigned underflow on a crafted image). */
    if (child.namelen == 0 || child.namelen > *remaining) {
        return -1;
    }

    char name[256];
    if (crimp_fs_seek64(ctx->f, *pos) != 0 ||
        fread(name, 1, child.namelen, ctx->f) != child.namelen) {
        return -1;
    }
    *pos += child.namelen;
    *remaining -= child.namelen;

    /* The encoder NUL-pads a short name up to the 4-byte-aligned namelen -
     * the real name never contains an embedded NUL (validated below), so
     * trimming trailing NULs recovers the true length. */
    size_t real_len = child.namelen;
    while (real_len > 0 && name[real_len - 1] == '\0') {
        real_len--;
    }
    /* crimp_fs_path_component_is_safe() already rejects a zero-length name
     * itself (fs_util.c) - no need to duplicate that check here. */
    if (!crimp_fs_path_component_is_safe(name, real_len)) {
        return -1;
    }

    char child_path[1024];
    int n;
    /* `name` was just validated by crimp_fs_path_component_is_safe() two
     * lines above - SonarCloud's c:S5145 (same BETA taint-analysis family
     * as c:S2083) doesn't recognize that call as clearing the taint.
     * NOSONAR */
    if (parent_path[0] == '\0') {
        n = snprintf(child_path, sizeof(child_path), "%.*s", (int)real_len, name); // NOSONAR
    } else {
        n = snprintf(child_path, sizeof(child_path), "%s/%.*s", parent_path, (int)real_len, // NOSONAR
                      name);
    }
    if (n < 0 || (size_t)n >= sizeof(child_path)) {
        return -1;
    }

    uint32_t filetype = child.mode & CRAMFS_S_IFMT;
    int is_dir = (filetype == CRAMFS_S_IFDIR);
    int is_reg = (filetype == CRAMFS_S_IFREG);

    if (crimp_fs_entry_list_add(ctx->out, child_path, is_dir, is_dir ? 0 : child.size) != 0) {
        return -1;
    }

    int rc = 0;
    if (ctx->output_dir != NULL) {
        char disk_path[1280];
        if (crimp_fs_join_output_path(ctx->output_dir, child_path, disk_path, sizeof(disk_path)) !=
            0) {
            rc = -1;
        } else if (is_dir) {
            rc = crimp_fs_make_directory(disk_path);
        } else if (is_reg) {
            rc = extract_regular_file(ctx->f, ctx->sb, &child, disk_path);
        }
        /* Symlinks and device/fifo/socket entries: listed above, nothing
         * extracted - same choice squashfs.c already made, for the same
         * reason (a symlink's target could point anywhere; extracting it
         * as a real filesystem symlink risks escaping output_dir). */
    }
    if (rc != 0) {
        return -1;
    }

    if (is_dir && walk_directory(ctx, child.offset, child.size, child_path, depth + 1) != 0) {
        return -1;
    }
    return 0;
}

/* No fixed round number here (unlike squashfs's MAX_DIR_DEPTH=32, chosen
 * for an 8KiB-metadata-cursor-per-frame function) - process_dir_entry's
 * stack frame is far lighter (a 12-byte inode buffer, a 256-byte name
 * buffer, and two ~1-1.3KB path buffers, no large fixed block buffer),
 * so the same depth cap that was proven safe for squashfs's heavier frame
 * carries an even larger safety margin here. Reused rather than
 * re-derived from scratch since it's already "far deeper than any real
 * firmware's directory tree" per squashfs's own reasoning. */
#define MAX_DIR_DEPTH 32

static int walk_directory(cramfs_walk_context *ctx, uint64_t offset, uint32_t size,
                           const char *parent_path, int depth) {
    if (depth > MAX_DIR_DEPTH) {
        return -1;
    }
    /* Every directory's entries region must stay within the superblock's
     * declared whole-image size - the same discipline extract_regular_file
     * already applies to data-block pointers, now applied here too (a
     * crafted or padded image with an offset pointing past the declared
     * boundary, but still inside the physical file, must not be walked as
     * if it were part of the legitimate tree). Guards the subtraction
     * against unsigned underflow by checking `offset` first. */
    if (offset > ctx->sb->size || (uint64_t)size > ctx->sb->size - offset) {
        return -1;
    }
    uint32_t remaining = size;
    uint64_t pos = offset;
    while (remaining > 0) {
        if (process_dir_entry(ctx, &pos, &remaining, parent_path, depth) != 0) {
            return -1;
        }
    }
    return 0;
}

int crimp_cramfs_list(const char *path, crimp_fs_entry_list *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    cramfs_super sb;
    if (read_superblock(f, &sb) != 0) {
        fclose(f);
        return -1;
    }

    crimp_fs_entry_list_init(out);
    cramfs_walk_context ctx = {f, &sb, out, NULL};
    int rc = walk_directory(&ctx, sb.root.offset, sb.root.size, "", 0);
    fclose(f);
    if (rc != 0) {
        crimp_fs_entry_list_free(out);
        return -1;
    }
    return 0;
}

int crimp_cramfs_extract(const char *path, const char *output_dir, crimp_fs_entry_list *out) {
    crimp_fs_entry_list_init(out);

    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    cramfs_super sb;
    if (read_superblock(f, &sb) != 0) {
        fclose(f);
        return -1;
    }
    if (crimp_fs_make_directory(output_dir) != 0) {
        fclose(f);
        crimp_fs_entry_list_free(out);
        return -1;
    }

    cramfs_walk_context ctx = {f, &sb, out, output_dir};
    int rc = walk_directory(&ctx, sb.root.offset, sb.root.size, "", 0);
    fclose(f);
    if (rc != 0) {
        crimp_fs_entry_list_free(out);
        return -1;
    }
    return 0;
}
