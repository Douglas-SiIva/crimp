#include "extract_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

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
    if (size > sizeof(c->buf)) {
        return -1;
    }
    if (compressed) {
        /* Milestone 2: real decompression (gzip first). Not supported yet. */
        return -1;
    }
    if (size > 0 && fread(c->buf, 1, size, c->f) != size) {
        return -1;
    }

    c->buf_len = size;
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
        if (c->buf_pos >= c->buf_len) {
            if (cursor_load_next_block(c) != 0) {
                return -1;
            }
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

typedef struct {
    uint16_t type;
    uint32_t inode_number;
    uint64_t dir_block_index;
    uint16_t dir_block_offset;
    uint64_t dir_size; /* raw file_size field, still 3 bytes larger than the real listing */
    uint64_t file_size;
} squashfs_inode;

static int read_inode(FILE *f, uint64_t inode_table_start, uint64_t block_offset,
                       uint16_t in_block_offset, squashfs_inode *out) {
    metadata_cursor c;
    if (cursor_init(&c, f, inode_table_start + block_offset, in_block_offset) != 0) {
        return -1;
    }

    uint16_t type, perm, uid_idx, gid_idx;
    uint32_t mtime, inode_number;
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

    switch (type) {
        case 1: { /* basic directory */
            uint32_t block_index, link_count, parent_inode;
            uint16_t file_size, blk_offset;
            if (cursor_read(&c, &block_index, 4) || cursor_read(&c, &link_count, 4) ||
                cursor_read(&c, &file_size, 2) || cursor_read(&c, &blk_offset, 2) ||
                cursor_read(&c, &parent_inode, 4)) {
                return -1;
            }
            out->dir_block_index = block_index;
            out->dir_block_offset = blk_offset;
            out->dir_size = file_size;
            break;
        }
        case 8: { /* extended directory */
            uint32_t link_count, file_size, block_index, parent_inode, xattr_index;
            uint16_t index_count, blk_offset;
            if (cursor_read(&c, &link_count, 4) || cursor_read(&c, &file_size, 4) ||
                cursor_read(&c, &block_index, 4) || cursor_read(&c, &parent_inode, 4) ||
                cursor_read(&c, &index_count, 2) || cursor_read(&c, &blk_offset, 2) ||
                cursor_read(&c, &xattr_index, 4)) {
                return -1;
            }
            /* Directory index entries (index_count of them) follow here —
             * an optimization for large directories, safe to ignore for
             * correctness: we still get every entry via the plain
             * directory-table walk below. */
            out->dir_block_index = block_index;
            out->dir_block_offset = blk_offset;
            out->dir_size = file_size;
            break;
        }
        case 2: { /* basic file */
            uint32_t blocks_start, frag_index, block_offset_f, file_size;
            if (cursor_read(&c, &blocks_start, 4) || cursor_read(&c, &frag_index, 4) ||
                cursor_read(&c, &block_offset_f, 4) || cursor_read(&c, &file_size, 4)) {
                return -1;
            }
            out->file_size = file_size;
            break;
        }
        case 9: { /* extended file */
            uint64_t blocks_start, file_size, sparse;
            uint32_t link_count, frag_index, block_offset_f, xattr_index;
            if (cursor_read(&c, &blocks_start, 8) || cursor_read(&c, &file_size, 8) ||
                cursor_read(&c, &sparse, 8) || cursor_read(&c, &link_count, 4) ||
                cursor_read(&c, &frag_index, 4) || cursor_read(&c, &block_offset_f, 4) ||
                cursor_read(&c, &xattr_index, 4)) {
                return -1;
            }
            out->file_size = file_size;
            break;
        }
        case 3: { /* basic symlink */
            uint32_t link_count, target_size;
            if (cursor_read(&c, &link_count, 4) || cursor_read(&c, &target_size, 4)) {
                return -1;
            }
            out->file_size = target_size;
            break;
        }
        case 10: { /* extended symlink */
            uint32_t link_count, target_size;
            if (cursor_read(&c, &link_count, 4) || cursor_read(&c, &target_size, 4)) {
                return -1;
            }
            out->file_size = target_size;
            break;
        }
        default:
            /* Device/fifo/socket inodes (4-7, 11-14): no content, nothing
             * else needed for a listing. */
            break;
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
#define MAX_DIR_DEPTH 32

static int walk_directory(FILE *f, const squashfs_superblock *sb, uint64_t dir_block_index,
                           uint16_t dir_block_offset, uint64_t dir_size, const char *parent_path,
                           crimp_squashfs_entry_list *out, int depth) {
    if (depth > MAX_DIR_DEPTH) {
        return -1;
    }
    if (dir_size < 4) {
        return 0; /* empty directory: no table entries */
    }
    uint64_t remaining = dir_size - 3;

    metadata_cursor c;
    if (cursor_init(&c, f, sb->directory_table_start + dir_block_index, dir_block_offset) != 0) {
        return -1;
    }

    while (remaining > 0) {
        if (remaining < 12) {
            return -1;
        }
        uint32_t count, start, inode_number_base;
        if (cursor_read(&c, &count, 4) || cursor_read(&c, &start, 4) ||
            cursor_read(&c, &inode_number_base, 4)) {
            return -1;
        }
        remaining -= 12;
        uint32_t entry_count = count + 1;
        if (entry_count > 256) {
            /* Spec caps a header group at 256 entries — anything higher is
             * a malformed or malicious directory table. */
            return -1;
        }

        for (uint32_t i = 0; i < entry_count; i++) {
            if (remaining < 8) {
                return -1;
            }
            uint16_t offset, type, name_size;
            int16_t inode_offset;
            if (cursor_read(&c, &offset, 2) || cursor_read(&c, &inode_offset, 2) ||
                cursor_read(&c, &type, 2) || cursor_read(&c, &name_size, 2)) {
                return -1;
            }
            remaining -= 8;

            uint16_t name_len = (uint16_t)(name_size + 1);
            if (remaining < name_len || name_len > 256) {
                return -1;
            }
            char name[257];
            if (cursor_read(&c, name, name_len) != 0) {
                return -1;
            }
            name[name_len] = '\0';
            remaining -= name_len;
            (void)inode_number_base;
            (void)inode_offset;
            (void)type; /* not trusted for is_dir — see below */

            char child_path[1024];
            if (parent_path[0] == '\0') {
                snprintf(child_path, sizeof(child_path), "%s", name);
            } else {
                snprintf(child_path, sizeof(child_path), "%s/%s", parent_path, name);
            }

            squashfs_inode child;
            if (read_inode(f, sb->inode_table_start, start, offset, &child) != 0) {
                return -1;
            }

            /* Directory entries carry their own cached `type` field
             * (real encoders keep it in sync with the target inode), but
             * this parser has to assume firmware images can be adversarial
             * — trusting that cache instead of the inode's real type would
             * let a crafted image mislabel a directory as a file and hide
             * its entire contents (weak credentials, exposed protocols,
             * whatever else) from every downstream detector. */
            int is_dir = (child.type == 1 || child.type == 8);
            if (entry_list_add(out, child_path, is_dir, is_dir ? 0 : child.file_size) != 0) {
                return -1;
            }

            if (is_dir) {
                if (walk_directory(f, sb, child.dir_block_index, child.dir_block_offset,
                                    child.dir_size, child_path, out, depth + 1) != 0) {
                    return -1;
                }
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
    if (read_inode(f, sb.inode_table_start, root_block, root_offset, &root) != 0) {
        fclose(f);
        crimp_squashfs_entry_list_free(out);
        return -1;
    }

    int rc = walk_directory(f, &sb, root.dir_block_index, root.dir_block_offset, root.dir_size,
                             "", out, 0);
    fclose(f);
    if (rc != 0) {
        crimp_squashfs_entry_list_free(out);
        return -1;
    }
    return 0;
}
