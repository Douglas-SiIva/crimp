#include "extract_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <zlib.h>

#include <errno.h>
#if defined(_WIN32)
#include <direct.h>
#include <windows.h>
#else
#include <sys/stat.h>
#endif

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

static int read_superblock(FILE *f, squashfs_superblock *sb) {
    if (fseek(f, 0, SEEK_SET) != 0) {
        return -1;
    }
    if (fread(sb, sizeof(*sb), 1, f) != 1) {
        return -1;
    }
    if (memcmp(&sb->magic, "hsqs", 4) != 0) {
        return -1;
    }
    return 0;
}

int crimp_squashfs_identify(const char *path, crimp_fs_info *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    squashfs_superblock sb;
    int rc = read_superblock(f, &sb);
    fclose(f);
    if (rc != 0) {
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

/* ---- Inode + directory table walk (issue #7, milestone 1: structure only,
 * no block decompression yet) ----
 *
 * Every reference into the inode or directory table (root_inode in the
 * superblock, a directory inode's block_index, a directory entry's start
 * field) packs into a 64-bit value: the upper 48 bits are a metadata block's
 * byte offset relative to the table's start, the lower 16 bits are a byte
 * offset within that block's *decompressed* 8KiB content. Metadata blocks
 * are read on demand (no whole-table pre-scan needed) via a small cursor
 * that transparently loads the next block once the current one is
 * exhausted — required because a single directory listing can span more
 * than one metadata block. See .claude/skills/squashfs-extraction/SKILL.md
 * for the full field-by-field spec this implements. */

#define METADATA_BLOCK_SIZE 8192

typedef struct {
    FILE *f;
    uint64_t next_block_offset; /* absolute file offset of the next block's header */
    uint8_t buf[METADATA_BLOCK_SIZE];
    uint16_t buf_len;
    uint16_t buf_pos;
} metadata_cursor;

/* fseek() takes a `long` offset, which is only 32 bits under the LLP64
 * model MinGW targets on Windows (this project's documented Windows build,
 * per CLAUDE.md) — casting a 64-bit table offset into that truncates
 * silently for offsets past ~2GB. Use the platform's real 64-bit seek. */
static int cursor_fseek64(FILE *f, uint64_t offset) {
#if defined(_WIN32)
    return _fseeki64(f, (long long)offset, SEEK_SET);
#else
    return fseeko(f, (off_t)offset, SEEK_SET);
#endif
}

/* SquashFS's "gzip" compressor (id 1, by far the most common in real
 * firmware alongside xz) is a raw zlib stream (RFC 1950 — zlib header +
 * adler32 trailer), not gzip-wrapped (RFC 1952) and not raw deflate
 * (RFC 1951) — confirmed against the kernel's squashfs zlib decompressor,
 * which uses zlib's default inflate init. zlib's single-shot uncompress()
 * expects exactly that framing, so it's a direct fit — no streaming state
 * needed since a metadata block's decompressed size is capped at 8KiB. */
static int inflate_block(uint8_t *dest, uint16_t *dest_len, const uint8_t *src,
                          uint16_t src_len) {
    uLongf out_len = METADATA_BLOCK_SIZE;
    if (uncompress(dest, &out_len, src, src_len) != Z_OK) {
        return -1;
    }
    *dest_len = (uint16_t)out_len;
    return 0;
}

static int cursor_load_next_block(metadata_cursor *c) {
    uint16_t hdr;
    if (cursor_fseek64(c->f, c->next_block_offset) != 0) {
        return -1;
    }
    if (fread(&hdr, sizeof(hdr), 1, c->f) != 1) {
        return -1;
    }

    uint16_t size = hdr & 0x7FFF;
    int compressed = (hdr & 0x8000) == 0;
    if (size > sizeof(c->buf) || size == 0) {
        return -1;
    }

    if (compressed) {
        /* Heap-allocated, not stack: this file already learned the hard
         * way (walk_directory's recursion depth cap) that stacking 8KiB
         * buffers is how you get a real stack overflow. */
        uint8_t *compressed_buf = (uint8_t *)malloc(size);
        if (!compressed_buf) {
            return -1;
        }
        if (fread(compressed_buf, 1, size, c->f) != size) {
            free(compressed_buf);
            return -1;
        }
        int rc = inflate_block(c->buf, &c->buf_len, compressed_buf, size);
        free(compressed_buf);
        if (rc != 0) {
            return -1;
        }
    } else {
        if (fread(c->buf, 1, size, c->f) != size) {
            return -1;
        }
        c->buf_len = size;
    }

    c->buf_pos = 0;
    c->next_block_offset += 2 + size;
    return 0;
}

static int cursor_init(metadata_cursor *c, FILE *f, uint64_t start_block_offset,
                        uint16_t start_in_block_offset) {
    c->f = f;
    c->next_block_offset = start_block_offset;
    c->buf_len = 0;
    c->buf_pos = 0;
    if (cursor_load_next_block(c) != 0) {
        return -1;
    }
    if (start_in_block_offset > c->buf_len) {
        return -1;
    }
    c->buf_pos = start_in_block_offset;
    return 0;
}

static int cursor_read(metadata_cursor *c, void *dst, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    while (n > 0) {
        if (c->buf_pos >= c->buf_len && cursor_load_next_block(c) != 0) {
            return -1;
        }
        size_t avail = (size_t)(c->buf_len - c->buf_pos);
        size_t take = n < avail ? n : avail;
        memcpy(d, c->buf + c->buf_pos, take);
        c->buf_pos = (uint16_t)(c->buf_pos + take);
        d += take;
        n -= take;
    }
    return 0;
}

/* SQUASHFS_INVALID_FRAG: sentinel meaning "no fragment, every block including
 * the tail is a full block" - not a real fragment table index. */
#define SQUASHFS_INVALID_FRAG 0xFFFFFFFFu

typedef struct {
    uint16_t type;
    uint32_t inode_number;
    uint64_t dir_block_index;
    uint16_t dir_block_offset;
    uint64_t dir_size; /* raw file_size field, still 3 bytes larger than the real listing */
    uint64_t file_size;

    /* Regular-file content location (types 2/9 only; zeroed otherwise) -
     * only read when the caller asks for it, since listing alone never
     * needs it. See read_inode()'s `want_content` parameter. */
    uint64_t content_blocks_start;
    uint32_t frag_index;
    uint32_t frag_block_offset;
    uint32_t *block_sizes; /* owned; one entry per full data block */
    uint32_t block_count;
} squashfs_inode;

/* Frees the block_sizes array a content-reading read_inode() call may have
 * allocated. Always safe to call, including on a zeroed/never-populated
 * inode. */
static void squashfs_inode_free(squashfs_inode *inode) {
    free(inode->block_sizes);
    inode->block_sizes = NULL;
    inode->block_count = 0;
}

/* Bounds the block_sizes[] array read_inode() allocates for a regular file.
 * A crafted extended-file inode can claim a near-UINT64_MAX file_size, which
 * would otherwise turn into an equally absurd block count and malloc size -
 * this caps it well above anything a real firmware component needs (at the
 * default 128KiB block size, 1<<20 blocks is a 128GiB file) while keeping
 * the worst-case allocation bounded (4MiB) regardless of what the image
 * claims. */
#define MAX_BLOCKS_PER_FILE (1u << 20)

/* Reads the block_sizes[] array immediately following a regular file
 * inode's fixed fields (still on the same metadata cursor `c`, which is why
 * this can't be deferred to a later, separate pass - the array's file
 * position only exists as "wherever the cursor is right now"). */
static int read_block_sizes(metadata_cursor *c, uint64_t file_size, uint64_t block_size,
                             uint32_t frag_index, squashfs_inode *out) {
    uint64_t nblocks64 = (frag_index == SQUASHFS_INVALID_FRAG)
                              ? (file_size + block_size - 1) / block_size
                              : file_size / block_size;
    if (nblocks64 > MAX_BLOCKS_PER_FILE) {
        return -1;
    }
    uint32_t nblocks = (uint32_t)nblocks64;
    if (nblocks == 0) {
        out->block_sizes = NULL;
        out->block_count = 0;
        return 0;
    }

    uint32_t *sizes = (uint32_t *)malloc((size_t)nblocks * sizeof(uint32_t));
    if (!sizes) {
        return -1;
    }
    for (uint32_t i = 0; i < nblocks; i++) {
        if (cursor_read(c, &sizes[i], 4) != 0) {
            free(sizes);
            return -1;
        }
    }
    out->block_sizes = sizes;
    out->block_count = nblocks;
    return 0;
}

/* Per-type field readers, split out of read_inode()'s switch so its own
 * cognitive complexity stays within the project's SonarCloud gate - same
 * rationale as process_dir_entry's extraction from walk_directory. */

static int read_basic_dir_fields(metadata_cursor *c, squashfs_inode *out) {
    uint32_t block_index;
    uint32_t link_count;
    uint32_t parent_inode;
    uint16_t file_size;
    uint16_t blk_offset;
    if (cursor_read(c, &block_index, 4) || cursor_read(c, &link_count, 4) ||
        cursor_read(c, &file_size, 2) || cursor_read(c, &blk_offset, 2) ||
        cursor_read(c, &parent_inode, 4)) {
        return -1;
    }
    out->dir_block_index = block_index;
    out->dir_block_offset = blk_offset;
    out->dir_size = file_size;
    return 0;
}

static int read_extended_dir_fields(metadata_cursor *c, squashfs_inode *out) {
    uint32_t link_count;
    uint32_t file_size;
    uint32_t block_index;
    uint32_t parent_inode;
    uint32_t xattr_index;
    uint16_t index_count;
    uint16_t blk_offset;
    if (cursor_read(c, &link_count, 4) || cursor_read(c, &file_size, 4) ||
        cursor_read(c, &block_index, 4) || cursor_read(c, &parent_inode, 4) ||
        cursor_read(c, &index_count, 2) || cursor_read(c, &blk_offset, 2) ||
        cursor_read(c, &xattr_index, 4)) {
        return -1;
    }
    /* Directory index entries (index_count of them) follow here - an
     * optimization for large directories, safe to ignore for correctness:
     * we still get every entry via the plain directory-table walk below. */
    out->dir_block_index = block_index;
    out->dir_block_offset = blk_offset;
    out->dir_size = file_size;
    return 0;
}

static int read_basic_file_fields(metadata_cursor *c, uint64_t block_size, int want_content,
                                   squashfs_inode *out) {
    uint32_t blocks_start;
    uint32_t frag_index;
    uint32_t block_offset_f;
    uint32_t file_size;
    if (cursor_read(c, &blocks_start, 4) || cursor_read(c, &frag_index, 4) ||
        cursor_read(c, &block_offset_f, 4) || cursor_read(c, &file_size, 4)) {
        return -1;
    }
    out->file_size = file_size;
    out->content_blocks_start = blocks_start;
    out->frag_index = frag_index;
    out->frag_block_offset = block_offset_f;
    if (want_content && read_block_sizes(c, file_size, block_size, frag_index, out) != 0) {
        return -1;
    }
    return 0;
}

static int read_extended_file_fields(metadata_cursor *c, uint64_t block_size, int want_content,
                                      squashfs_inode *out) {
    uint64_t blocks_start;
    uint64_t file_size;
    uint64_t sparse;
    uint32_t link_count;
    uint32_t frag_index;
    uint32_t block_offset_f;
    uint32_t xattr_index;
    if (cursor_read(c, &blocks_start, 8) || cursor_read(c, &file_size, 8) ||
        cursor_read(c, &sparse, 8) || cursor_read(c, &link_count, 4) ||
        cursor_read(c, &frag_index, 4) || cursor_read(c, &block_offset_f, 4) ||
        cursor_read(c, &xattr_index, 4)) {
        return -1;
    }
    out->file_size = file_size;
    out->content_blocks_start = blocks_start;
    out->frag_index = frag_index;
    out->frag_block_offset = block_offset_f;
    if (want_content && read_block_sizes(c, file_size, block_size, frag_index, out) != 0) {
        return -1;
    }
    return 0;
}

/* Shared by basic (type 3) and extended (type 10) symlinks - identical
 * field layout, only the inode type tag differs. */
static int read_symlink_fields(metadata_cursor *c, squashfs_inode *out) {
    uint32_t link_count;
    uint32_t target_size;
    if (cursor_read(c, &link_count, 4) || cursor_read(c, &target_size, 4)) {
        return -1;
    }
    out->file_size = target_size;
    return 0;
}

static int read_inode(FILE *f, uint64_t inode_table_start, uint64_t block_offset,
                       uint16_t in_block_offset, uint64_t block_size, int want_content,
                       squashfs_inode *out) {
    metadata_cursor c;
    if (cursor_init(&c, f, inode_table_start + block_offset, in_block_offset) != 0) {
        return -1;
    }

    uint16_t type;
    uint16_t perm;
    uint16_t uid_idx;
    uint16_t gid_idx;
    uint32_t mtime;
    uint32_t inode_number;
    if (cursor_read(&c, &type, 2) || cursor_read(&c, &perm, 2) || cursor_read(&c, &uid_idx, 2) ||
        cursor_read(&c, &gid_idx, 2) || cursor_read(&c, &mtime, 4) ||
        cursor_read(&c, &inode_number, 4)) {
        return -1;
    }
    (void)perm;
    (void)uid_idx;
    (void)gid_idx;
    (void)mtime;

    memset(out, 0, sizeof(*out));
    out->type = type;
    out->inode_number = inode_number;

    int rc = 0;
    switch (type) {
        case 1:
            rc = read_basic_dir_fields(&c, out);
            break;
        case 8:
            rc = read_extended_dir_fields(&c, out);
            break;
        case 2:
            rc = read_basic_file_fields(&c, block_size, want_content, out);
            break;
        case 9:
            rc = read_extended_file_fields(&c, block_size, want_content, out);
            break;
        case 3:
        case 10:
            rc = read_symlink_fields(&c, out);
            break;
        default:
            /* Device/fifo/socket inodes (4-7, 11-14): no content, nothing
             * else needed for a listing. */
            break;
    }
    return rc;
}

/* Historical mksquashfs/kernel max block size. Real images use 128KiB by
 * default; nothing legitimate needs more than this. Rejecting anything
 * larger bounds every future decompression buffer to a sane size regardless
 * of what a crafted superblock claims - the actual decompression-bomb
 * defense for milestone 2b's data blocks (metadata blocks already got this
 * for free from their fixed 8KiB buffer). */
#define MAX_SQUASHFS_BLOCK_SIZE (1u << 20)

/* Spec/mksquashfs minimum - anything smaller isn't just unusual, it's
 * invalid, and would otherwise surface later as a confusing generic
 * failure (e.g. hitting MAX_BLOCKS_PER_FILE on any realistically-sized
 * file) instead of being rejected here with a clear cause. */
#define MIN_SQUASHFS_BLOCK_SIZE 4096u

static int validate_block_size(uint32_t block_size) {
    if (block_size < MIN_SQUASHFS_BLOCK_SIZE || block_size > MAX_SQUASHFS_BLOCK_SIZE) {
        return -1;
    }
    if ((block_size & (block_size - 1)) != 0) { /* spec requires power of two */
        return -1;
    }
    return 0;
}

/* Windows reserves these as device names regardless of extension or case
 * ("con", "CON", "con.txt" are all the console device, not a creatable
 * file) - a real hazard here since this project's documented build target
 * is Windows/MinGW, and an image built on Linux (where these are ordinary
 * filenames) can carry one without anything else being wrong with it. */
static const char *const WINDOWS_RESERVED_NAMES[] = {
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
    "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
    "lpt6", "lpt7", "lpt8", "lpt9",
};
#define WINDOWS_RESERVED_NAME_COUNT \
    (sizeof(WINDOWS_RESERVED_NAMES) / sizeof(WINDOWS_RESERVED_NAMES[0]))

static int is_windows_reserved_name(const char *name, size_t len) {
    size_t base_len = 0;
    while (base_len < len && name[base_len] != '.') {
        base_len++;
    }
    if (base_len == 0 || base_len > 4) {
        return 0; /* every reserved name's base is 3-4 chars */
    }
    for (size_t r = 0; r < WINDOWS_RESERVED_NAME_COUNT; r++) {
        const char *reserved = WINDOWS_RESERVED_NAMES[r];
        if (strlen(reserved) != base_len) {
            continue;
        }
        int match = 1;
        for (size_t i = 0; i < base_len; i++) {
            char c = name[i];
            if (c >= 'A' && c <= 'Z') {
                c = (char)(c - 'A' + 'a');
            }
            if (c != reserved[i]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return 1;
        }
    }
    return 0;
}

/* A directory-table entry name is untrusted. Reject anything that could
 * turn "output_dir + name" into a path escaping output_dir once joined
 * (".", "..", any embedded path separator - both "/" and "\\", since a
 * name crafted on one platform must not escape when Crimp runs on the
 * other - or drive-letter colon), anything that would silently truncate
 * once C-string functions touch it (an embedded NUL byte - name_len is
 * trusted for bounds-checking raw bytes, but %s/strlen stop at the first
 * NUL regardless, so two differently-named entries could collide onto the
 * same disk path), or a Windows-reserved device name. Real mksquashfs
 * never produces any of these, so this can't reject legitimate images -
 * only crafted (or, for the device-name case, merely unlucky) ones. */
static int path_component_is_safe(const char *name, size_t len) {
    /* len is always >= 1 here: the caller derives it from the on-disk
     * name_size field as name_size + 1 (off-by-one encoded), which can
     * never underflow to 0. */
    if (len == 1 && name[0] == '.') {
        return 0;
    }
    if (len == 2 && name[0] == '.' && name[1] == '.') {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c == '/' || c == '\\' || c == ':' || c == '\0') {
            return 0;
        }
    }
    if (is_windows_reserved_name(name, len)) {
        return 0;
    }
    return 1;
}

/* Returns 1 if `path` exists and is a directory, 0 otherwise (including on
 * stat failure). */
static int path_is_existing_directory(const char *path) {
#if defined(_WIN32)
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

/* mkdir() reporting EEXIST only means *something* is already there - not
 * necessarily a directory. Without checking, a stale regular file left at
 * this path (e.g. from a previous extraction run into the same output_dir)
 * would make this report success while the walk still believes it can
 * recurse into a real directory, turning every child underneath into a
 * confusing failure far from the actual cause. */
static int make_directory(const char *path) {
#if defined(_WIN32)
    if (_mkdir(path) == 0) {
        return 0;
    }
    return (errno == EEXIST && path_is_existing_directory(path)) ? 0 : -1;
#else
    /* Owner-only: extracted firmware content can legitimately contain
     * secrets (private keys, credentials - the exact things this tool's
     * own detectors look for), so the extraction tree shouldn't be
     * world-readable by default. */
    if (mkdir(path, 0700) == 0) {
        return 0;
    }
    return (errno == EEXIST && path_is_existing_directory(path)) ? 0 : -1;
#endif
}

/* Joins output_dir and rel_path, rejecting (rather than silently
 * truncating) anything that doesn't fit - a truncated path could resolve
 * to somewhere unintended just as easily as a traversal could. */
static int join_output_path(const char *output_dir, const char *rel_path, char *out,
                             size_t out_cap) {
    int n = snprintf(out, out_cap, "%s/%s", output_dir, rel_path);
    if (n < 0 || (size_t)n >= out_cap) {
        return -1;
    }
    return 0;
}

/* Fragment table: a raw (uncompressed) array of u64 metadata-block offsets
 * at fragment_table_start, one per 512 fragment entries; each such block
 * holds up to 512 16-byte entries (start u64, size u32 with bit 24 marking
 * "stored uncompressed", unused u32). See
 * .claude/skills/squashfs-extraction/SKILL.md. */
#define FRAGMENTS_PER_METADATA_BLOCK 512

static int read_fragment_entry(FILE *f, const squashfs_superblock *sb, uint32_t frag_index,
                                uint64_t *out_start, uint32_t *out_size, int *out_compressed) {
    if (frag_index >= sb->fragments) {
        return -1;
    }
    uint32_t block_idx = frag_index / FRAGMENTS_PER_METADATA_BLOCK;
    uint32_t entry_idx = frag_index % FRAGMENTS_PER_METADATA_BLOCK;

    uint64_t lookup_offset = sb->fragment_table_start + (uint64_t)block_idx * 8;
    if (cursor_fseek64(f, lookup_offset) != 0) {
        return -1;
    }
    uint64_t meta_block_offset;
    if (fread(&meta_block_offset, sizeof(meta_block_offset), 1, f) != 1) {
        return -1;
    }

    metadata_cursor c;
    if (cursor_init(&c, f, meta_block_offset, (uint16_t)(entry_idx * 16)) != 0) {
        return -1;
    }

    uint64_t start;
    uint32_t size_field;
    uint32_t unused;
    if (cursor_read(&c, &start, 8) || cursor_read(&c, &size_field, 4) ||
        cursor_read(&c, &unused, 4)) {
        return -1;
    }
    (void)unused;

    *out_start = start;
    *out_compressed = (size_field & (1u << 24)) == 0;
    *out_size = size_field & 0xFFFFFFu;
    return 0;
}

/* Reads one on-disk block (a full data block or a whole fragment block) at
 * `offset`, of `size` bytes, decompressing it into `dest` (capacity
 * `dest_cap`, always sb->block_size - the decompression-bomb cap) unless
 * `compressed` is false. */
static int read_and_inflate_block(FILE *f, uint64_t offset, uint32_t size, int compressed,
                                   uint8_t *dest, uint32_t dest_cap, uint32_t *dest_len) {
    if (size > dest_cap) {
        return -1;
    }
    if (cursor_fseek64(f, offset) != 0) {
        return -1;
    }

    if (!compressed) {
        if (fread(dest, 1, size, f) != size) {
            return -1;
        }
        *dest_len = size;
        return 0;
    }

    uint8_t *compressed_buf = (uint8_t *)malloc(size);
    if (!compressed_buf) {
        return -1;
    }
    if (fread(compressed_buf, 1, size, f) != size) {
        free(compressed_buf);
        return -1;
    }
    uLongf out_len = dest_cap;
    int rc = uncompress(dest, &out_len, compressed_buf, size);
    free(compressed_buf);
    if (rc != Z_OK) {
        return -1;
    }
    *dest_len = (uint32_t)out_len;
    return 0;
}

/* Writes one full data block (a "hole" if `raw`'s size is 0, otherwise
 * read+decompressed from `block_offset`) to `out`, verifying its
 * decompressed length matches `expected_len` exactly. Split out of
 * extract_regular_file()'s loop so that function needs only one `break` on
 * failure, not two. */
static int write_data_block(FILE *f, FILE *out, uint64_t block_offset, uint32_t raw,
                             uint64_t expected_len, uint8_t *block_buf, uint32_t block_size) {
    uint32_t size = raw & 0xFFFFFFu;
    int compressed = (raw & (1u << 24)) == 0;
    uint32_t dest_len;
    if (size == 0) {
        /* A hole (sparse block): file_size bytes of zero, nothing on disk. */
        memset(block_buf, 0, (size_t)expected_len);
        dest_len = (uint32_t)expected_len;
    } else if (read_and_inflate_block(f, block_offset, size, compressed, block_buf, block_size,
                                       &dest_len) != 0) {
        return -1;
    }
    /* SonarCloud's c:S2083 (path-injection taint rule) flags this write as
     * a "tainted value leaking" - its dataflow engine doesn't recognize
     * path_component_is_safe() + join_output_path() (this file's actual
     * sanitization, applied before `out`'s path was ever built) as a
     * taint-clearing boundary, so it still treats `out` as carrying
     * untrusted path influence here. That sanitization was verified against
     * a deliberately crafted traversal image (see tests/fixtures/README.md
     * and this PR's description) - writing the file's own decompressed
     * bytes to a path already proven safe is the extraction feature
     * working as intended, not a leak. NOSONAR */
    if (dest_len != expected_len || fwrite(block_buf, 1, dest_len, out) != dest_len) { // NOSONAR
        return -1;
    }
    return 0;
}

/* Extracts one regular file's content to `disk_path`: every full data block
 * (from content_blocks_start, sized per block_sizes[]) plus, if the file
 * uses one, its tail slice of a shared fragment block. */
static int extract_regular_file(FILE *f, const squashfs_superblock *sb,
                                 const squashfs_inode *inode, const char *disk_path) {
    FILE *out = fopen(disk_path, "wb");
    if (!out) {
        return -1;
    }

    uint8_t *block_buf = (uint8_t *)malloc(sb->block_size);
    if (!block_buf) {
        fclose(out);
        return -1;
    }

    int ok = 1;
    uint64_t block_offset = inode->content_blocks_start;
    uint64_t bytes_before = 0;
    for (uint32_t i = 0; ok && i < inode->block_count; i++) {
        /* Every full block is exactly block_size, except the very last one
         * when the file has no fragment tail (frag_index invalid) - that
         * last block absorbs whatever remainder didn't divide evenly. */
        uint64_t expected_len = sb->block_size;
        if (bytes_before + expected_len > inode->file_size) {
            expected_len = inode->file_size - bytes_before;
        }

        if (write_data_block(f, out, block_offset, inode->block_sizes[i], expected_len, block_buf,
                              sb->block_size) != 0) {
            ok = 0;
            break;
        }
        block_offset += inode->block_sizes[i] & 0xFFFFFFu;
        bytes_before += expected_len;
    }

    if (ok && inode->frag_index != SQUASHFS_INVALID_FRAG) {
        uint64_t frag_start;
        uint32_t frag_size;
        int frag_compressed;
        uint64_t tail_len = inode->file_size - bytes_before;
        uint32_t frag_dest_len = 0;
        if (read_fragment_entry(f, sb, inode->frag_index, &frag_start, &frag_size,
                                 &frag_compressed) != 0 ||
            read_and_inflate_block(f, frag_start, frag_size, frag_compressed, block_buf,
                                   sb->block_size, &frag_dest_len) != 0) {
            ok = 0;
        } else if ((uint64_t)inode->frag_block_offset + tail_len > frag_dest_len) {
            ok = 0; /* fragment doesn't actually contain the claimed tail range */
        } else if (fwrite(block_buf + inode->frag_block_offset, 1, (size_t)tail_len, out) != // NOSONAR
                   (size_t)tail_len) {
            /* Same c:S2083 false positive as write_data_block()'s fwrite - see
             * that comment for why `out`'s path is already proven safe here. */
            ok = 0;
        }
    }

    free(block_buf);
    fclose(out);
    if (!ok) {
        /* Don't leave a truncated/partial file behind - a caller that
         * inspects output_dir independently of this function's return
         * value (a detector walking the tree, say) has no way to tell a
         * genuinely short file from one that stopped mid-write. */
        remove(disk_path);
        return -1;
    }
    return 0;
}

void crimp_squashfs_entry_list_init(crimp_squashfs_entry_list *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int entry_list_add(crimp_squashfs_entry_list *list, const char *path, int is_dir,
                           uint64_t size) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        crimp_squashfs_entry *items = (crimp_squashfs_entry *)realloc(
            list->items, new_capacity * sizeof(crimp_squashfs_entry));
        if (!items) {
            return -1;
        }
        list->items = items;
        list->capacity = new_capacity;
    }

    crimp_squashfs_entry *e = &list->items[list->count];
    e->path = strdup(path);
    if (!e->path) {
        return -1;
    }
    e->is_dir = is_dir;
    e->size = size;
    list->count++;
    return 0;
}

void crimp_squashfs_entry_list_free(crimp_squashfs_entry_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].path);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* MAX_DIR_DEPTH's rationale is documented on walk_directory below, next to
 * the code that actually enforces it. */
#define MAX_DIR_DEPTH 32

/* Bundles the arguments that stay constant across the whole walk (only
 * dir_block_index/offset/size, parent_path and depth actually vary between
 * recursive calls) — keeps walk_directory under SonarCloud's 7-parameter
 * limit. */
typedef struct {
    FILE *f;
    const squashfs_superblock *sb;
    crimp_squashfs_entry_list *out;
    const char *output_dir; /* NULL for crimp_squashfs_list (listing only, no writes) */
} walk_context;

static int walk_directory(const walk_context *ctx, uint64_t dir_block_index,
                           uint16_t dir_block_offset, uint64_t dir_size, const char *parent_path,
                           int depth);

/* Reads one directory-table entry, resolves its inode, records it, and
 * recurses into it if it's really a directory. Split out of walk_directory
 * so each function's own cognitive complexity and nesting depth stay within
 * the project's SonarCloud gate — this also happens to make the "merge
 * nested is_dir/recurse check" cleanup natural. */
static int process_dir_entry(const walk_context *ctx, metadata_cursor *c, uint64_t *remaining,
                              uint32_t start, const char *parent_path, int depth) {
    if (*remaining < 8) {
        return -1;
    }
    uint16_t offset;
    uint16_t type;
    uint16_t name_size;
    int16_t inode_offset;
    if (cursor_read(c, &offset, 2) || cursor_read(c, &inode_offset, 2) ||
        cursor_read(c, &type, 2) || cursor_read(c, &name_size, 2)) {
        return -1;
    }
    *remaining -= 8;
    (void)inode_offset;
    (void)type; /* not trusted for is_dir — see below */

    uint16_t name_len = (uint16_t)(name_size + 1);
    if (*remaining < name_len || name_len > 256) {
        return -1;
    }
    char name[257];
    if (cursor_read(c, name, name_len) != 0) {
        return -1;
    }
    name[name_len] = '\0';
    *remaining -= name_len;

    /* Untrusted: a crafted image's entry name could otherwise turn
     * "parent_path/name" into a traversal once joined with an output_dir
     * during extraction. Enforced for listing too, not just extraction -
     * a real image never has such a name, so this only ever rejects
     * malformed/adversarial ones. */
    if (!path_component_is_safe(name, name_len)) {
        return -1;
    }

    char child_path[1024];
    int child_path_len;
    if (parent_path[0] == '\0') {
        child_path_len = snprintf(child_path, sizeof(child_path), "%s", name);
    } else {
        child_path_len = snprintf(child_path, sizeof(child_path), "%s/%s", parent_path, name);
    }
    /* A silently truncated path is exactly as unsafe as a traversal - it
     * could collide with an unrelated, shorter path (see join_output_path's
     * same reasoning below). Deep enough trees with long enough names can
     * genuinely overflow this buffer; reject rather than guess. */
    if (child_path_len < 0 || (size_t)child_path_len >= sizeof(child_path)) {
        return -1;
    }

    squashfs_inode child;
    int want_content = ctx->output_dir != NULL;
    if (read_inode(ctx->f, ctx->sb->inode_table_start, start, offset, ctx->sb->block_size,
                    want_content, &child) != 0) {
        return -1;
    }

    /* Directory entries carry their own cached `type` field (real encoders
     * keep it in sync with the target inode), but this parser has to
     * assume firmware images can be adversarial — trusting that cache
     * instead of the inode's real type would let a crafted image mislabel
     * a directory as a file and hide its entire contents (weak
     * credentials, exposed protocols, whatever else) from every
     * downstream detector. */
    int is_dir = (child.type == 1 || child.type == 8);
    if (entry_list_add(ctx->out, child_path, is_dir, is_dir ? 0 : child.file_size) != 0) {
        squashfs_inode_free(&child);
        return -1;
    }

    int rc = 0;
    if (ctx->output_dir != NULL) {
        char disk_path[1280];
        if (join_output_path(ctx->output_dir, child_path, disk_path, sizeof(disk_path)) != 0) {
            rc = -1;
        } else if (is_dir) {
            rc = make_directory(disk_path);
        } else if (child.type == 2 || child.type == 9) {
            rc = extract_regular_file(ctx->f, ctx->sb, &child, disk_path);
        }
        /* Other types (symlink, device, fifo, socket) have no content to
         * write - listed above, nothing extracted, not an error. */
    }
    squashfs_inode_free(&child);
    if (rc != 0) {
        return -1;
    }

    if (is_dir && walk_directory(ctx, child.dir_block_index, child.dir_block_offset,
                                  child.dir_size, child_path, depth + 1) != 0) {
        return -1;
    }
    return 0;
}

/* SquashFS caps a single directory listing at 256 entries per header group,
 * but a directory can have many such groups — no fixed cap on total
 * children, so recursion depth is bounded by the real tree, not this walk.
 *
 * `depth` guards against a crafted image whose directory table points a
 * subdirectory back at itself or an ancestor: without a cap, that would
 * recurse indefinitely and blow the stack. Each walk_directory frame holds
 * an 8KiB metadata_cursor (~9.6KB per frame with the rest of its locals),
 * so the cap has to be picked with that in mind, not just "a big round
 * number" — 256 levels (~2.5MB) reliably crashed in testing on this
 * project's default Windows/MinGW build. 32 levels (~300KB worst case) is
 * still far deeper than any real firmware's directory tree while leaving a
 * large safety margin against smaller stacks (worker threads, constrained
 * environments). */
static int walk_directory(const walk_context *ctx, uint64_t dir_block_index,
                           uint16_t dir_block_offset, uint64_t dir_size, const char *parent_path,
                           int depth) {
    if (depth > MAX_DIR_DEPTH) {
        return -1;
    }
    if (dir_size < 4) {
        return 0; /* empty directory: no table entries */
    }
    uint64_t remaining = dir_size - 3;

    metadata_cursor c;
    if (cursor_init(&c, ctx->f, ctx->sb->directory_table_start + dir_block_index,
                     dir_block_offset) != 0) {
        return -1;
    }

    while (remaining > 0) {
        if (remaining < 12) {
            return -1;
        }
        uint32_t count;
        uint32_t start;
        uint32_t inode_number_base;
        if (cursor_read(&c, &count, 4) || cursor_read(&c, &start, 4) ||
            cursor_read(&c, &inode_number_base, 4)) {
            return -1;
        }
        remaining -= 12;
        (void)inode_number_base;

        uint32_t entry_count = count + 1;
        if (entry_count > 256) {
            /* Spec caps a header group at 256 entries — anything higher is
             * a malformed or malicious directory table. */
            return -1;
        }

        for (uint32_t i = 0; i < entry_count; i++) {
            if (process_dir_entry(ctx, &c, &remaining, start, parent_path, depth) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

int crimp_squashfs_list(const char *path, crimp_squashfs_entry_list *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    squashfs_superblock sb;
    if (read_superblock(f, &sb) != 0) {
        fclose(f);
        return -1;
    }

    crimp_squashfs_entry_list_init(out);

    uint64_t root_block = sb.root_inode >> 16;
    uint16_t root_offset = (uint16_t)(sb.root_inode & 0xFFFF);

    squashfs_inode root;
    if (read_inode(f, sb.inode_table_start, root_block, root_offset, sb.block_size, 0, &root) !=
        0) {
        fclose(f);
        crimp_squashfs_entry_list_free(out);
        return -1;
    }

    walk_context ctx = {f, &sb, out, NULL};
    int rc = walk_directory(&ctx, root.dir_block_index, root.dir_block_offset, root.dir_size, "",
                             0);
    fclose(f);
    if (rc != 0) {
        crimp_squashfs_entry_list_free(out);
        return -1;
    }
    return 0;
}

/* Issue #7 milestone 2b: like crimp_squashfs_list, but also writes every
 * regular file's real (decompressed) content under output_dir, mirroring
 * the image's directory structure, and creates directories as needed.
 * output_dir must already exist (created by the caller, or by us as a
 * plain mkdir here) - every path written beneath it comes from
 * path_component_is_safe()-checked entry names, so nothing can escape it. */
int crimp_squashfs_extract(const char *path, const char *output_dir,
                            crimp_squashfs_entry_list *out) {
    /* Initialized before any failure path below, unlike crimp_squashfs_list
     * (whose fopen/read_superblock failures leave `out` untouched) - this
     * function's callers are extracting to disk on a code path that's more
     * naturally paired with "always free `out` when done", so make that
     * always safe rather than conditional on which check failed. */
    crimp_squashfs_entry_list_init(out);

    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    squashfs_superblock sb;
    if (read_superblock(f, &sb) != 0) {
        fclose(f);
        return -1;
    }
    if (validate_block_size(sb.block_size) != 0) {
        fclose(f);
        return -1;
    }
    if (make_directory(output_dir) != 0) {
        fclose(f);
        return -1;
    }

    uint64_t root_block = sb.root_inode >> 16;
    uint16_t root_offset = (uint16_t)(sb.root_inode & 0xFFFF);

    squashfs_inode root;
    if (read_inode(f, sb.inode_table_start, root_block, root_offset, sb.block_size, 0, &root) !=
        0) {
        fclose(f);
        crimp_squashfs_entry_list_free(out);
        return -1;
    }

    walk_context ctx = {f, &sb, out, output_dir};
    int rc = walk_directory(&ctx, root.dir_block_index, root.dir_block_offset, root.dir_size, "",
                             0);
    fclose(f);
    if (rc != 0) {
        crimp_squashfs_entry_list_free(out);
        return -1;
    }
    return 0;
}
