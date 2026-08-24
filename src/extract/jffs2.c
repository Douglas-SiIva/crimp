#include "extract_internal.h"
#include "fs_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* JFFS2 (issue #8). See .claude/skills/jffs2-extraction/SKILL.md for the
 * full field-by-field spec and how it was derived/validated - every struct
 * size and constant below was cross-checked against real bytes from a
 * `mkfs.jffs2`-built image (not trusted from a single summarized source;
 * two struct sizes from an initial pass turned out wrong by the same
 * "don't trust one source" margin cramfs's superblock size already taught).
 *
 * Structurally very different from squashfs/cramfs: there's no superblock
 * and no single "walk from here" pointer. JFFS2 is a log-structured
 * filesystem (designed for raw flash, which can't rewrite in place) - the
 * whole image is a sequential stream of small "nodes" (dirent = a directory
 * entry write, inode = a file's metadata + a chunk of its content), and
 * later nodes for the same (parent,name) or the same inode number
 * supersede earlier ones (tracked via each node's `version` field - higher
 * wins). Making sense of the tree means scanning the *entire* log once,
 * then resolving "what's the current, live state" from everything seen. */

#define JFFS2_MAGIC 0x1985u

#define JFFS2_NODETYPE_DIRENT 0xe001u
#define JFFS2_NODETYPE_INODE 0xe002u

#define JFFS2_COMMON_HEADER_SIZE 12 /* magic(2) + nodetype(2) + totlen(4) + hdr_crc(4) */
/* dirent's own fields (after the common header): pino(4) version(4) ino(4)
 * mctime(4) nsize(1) type(1) unused(2) node_crc(4) name_crc(4) = 28. Total
 * on-disk header including the common 12 bytes is 40 - the two numbers
 * were briefly confused for each other while writing this constant, caught
 * by the same real-image cross-check discipline that already caught two
 * other struct-size mistakes in this file's research (see SKILL.md): a
 * totlen=51 dirent for an 11-byte name only balances against a 28-byte
 * dirent-specific size (51 - 12 - 28 = 11), not 40. */
#define JFFS2_DIRENT_FIXED_SIZE 28
#define JFFS2_INODE_FIXED_SIZE 56 /* raw_inode's own fields, after the common header */

#define JFFS2_COMPR_NONE 0u
#define JFFS2_COMPR_ZLIB 6u

#define JFFS2_ROOT_INO 1u

#define JFFS2_S_IFMT 0xF000u
#define JFFS2_S_IFDIR 0x4000u
#define JFFS2_S_IFREG 0x8000u

/* One dirent node, as scanned from the log - `name` is owned. `name_len` is
 * the true on-disk length (the number of bytes actually written, not
 * strlen(name)) - a name can legally contain an embedded NUL byte on disk
 * (nsize is a plain byte count, not a C-string length), and relying on
 * strlen() anywhere below it would silently truncate that name to its
 * pre-NUL prefix, defeating crimp_fs_path_component_is_safe()'s own
 * embedded-NUL rejection (which only sees what length it's told) and
 * letting two distinct on-disk entries compare/sort as identical. */
typedef struct {
    uint32_t pino;
    uint32_t version;
    uint32_t ino; /* 0 means "this name was deleted" */
    char *name;
    size_t name_len;
} jffs2_dirent_rec;

/* One inode (file-metadata+content-fragment) node, as scanned from the log.
 * `file_offset` is this node's absolute position in the *image* (so its
 * data payload can be re-read later without keeping the whole log in
 * memory); `frag_offset`/`dsize` describe where its decompressed bytes
 * belong within the *target file's* content. */
typedef struct {
    uint32_t ino;
    uint32_t version;
    uint32_t mode;
    uint32_t isize; /* the file's total size as of this write */
    uint32_t frag_offset;
    uint32_t csize;
    uint32_t dsize;
    uint8_t compr;
    uint64_t file_offset; /* absolute offset in the image of this node's data payload */
} jffs2_inode_rec;

typedef struct {
    jffs2_dirent_rec *items;
    size_t count;
    size_t capacity;
} dirent_list;

typedef struct {
    jffs2_inode_rec *items;
    size_t count;
    size_t capacity;
} inode_rec_list;

static int dirent_list_add(dirent_list *list, uint32_t pino, uint32_t version, uint32_t ino,
                            const char *name, size_t name_len) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 64 : list->capacity * 2;
        jffs2_dirent_rec *items =
            (jffs2_dirent_rec *)realloc(list->items, new_capacity * sizeof(jffs2_dirent_rec));
        if (!items) {
            return -1;
        }
        list->items = items;
        list->capacity = new_capacity;
    }
    char *name_copy = (char *)malloc(name_len + 1);
    if (!name_copy) {
        return -1;
    }
    memcpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';

    jffs2_dirent_rec *r = &list->items[list->count++];
    r->pino = pino;
    r->version = version;
    r->ino = ino;
    r->name = name_copy;
    r->name_len = name_len;
    return 0;
}

static void dirent_list_free(dirent_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].name);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int inode_rec_list_add(inode_rec_list *list, const jffs2_inode_rec *rec) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 64 : list->capacity * 2;
        jffs2_inode_rec *items =
            (jffs2_inode_rec *)realloc(list->items, new_capacity * sizeof(jffs2_inode_rec));
        if (!items) {
            return -1;
        }
        list->items = items;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = *rec;
    return 0;
}

/* JFFS2 has no fixed/known erase-block size at the reader level (unlike
 * cramfs's fixed page size) - a real image is written across many erase
 * blocks (commonly 64KiB-256KiB), and mkfs.jffs2/real flash both pad the
 * unused remainder of each erase block with filler (seen as 0xFF in
 * practice - confirmed against a real image) rather than splitting a node
 * across a block boundary. That padding means a plain "stop at the first
 * non-magic byte" scan stops at the *first* erase block's leftover space,
 * missing every block after it - confirmed against a real 12MB multi-block
 * image, where a naive scan only reached the second erase block before
 * stopping. Skip forward, 4-byte-aligned (matching every node's own
 * alignment), until either a valid magic is found again (a fresh erase
 * block's cleanmarker or first real node) or the image genuinely ends.
 * Reads in chunks rather than one syscall per candidate position, since a
 * real gap can be tens of KiB of filler. */
#define GAP_SCAN_CHUNK 65536

static int find_next_node(FILE *f, uint64_t start, uint64_t image_size, int big_endian,
                           uint64_t *out_pos) {
    uint8_t buf[GAP_SCAN_CHUNK];
    uint64_t pos = start;
    while (pos + 2 <= image_size) {
        if (crimp_fs_seek64(f, pos) != 0) {
            return -1;
        }
        uint64_t remaining = image_size - pos;
        size_t want = remaining < GAP_SCAN_CHUNK ? (size_t)remaining : GAP_SCAN_CHUNK;
        size_t got = fread(buf, 1, want, f);
        if (got < 2) {
            return -1;
        }
        for (size_t i = 0; i + 1 < got; i += 4) {
            if (crimp_fs_decode_u16(buf + i, big_endian) == JFFS2_MAGIC) {
                *out_pos = pos + i;
                return 0;
            }
        }
        /* `got < 4` rounds down to zero progress below, which would spin
         * forever re-reading the same trailing 2-3 bytes (a real hang,
         * caught by a genuinely tiny fixture, not just a theoretical
         * concern) - fewer than 4 bytes can never contain another
         * 4-byte-aligned candidate anyway, so this is always the end of
         * the search, not just of this chunk. */
        if (got < 4) {
            break;
        }
        pos += ((uint64_t)got / 4) * 4;
        if (got < want) {
            break; /* short read: reached end of file */
        }
    }
    return -1; /* genuinely no more valid nodes before image_size */
}

/* Scans the entire image once, collecting every dirent and inode node into
 * `dirents`/`inodes`. Skips forward across erase-block padding gaps (see
 * find_next_node above) and stops (successfully) once no further valid
 * node exists before `image_size`. Returns 0 on success (including "found
 * zero nodes" for a tiny/empty image), -1 on a malformed node (bad totlen,
 * truncated read) partway through otherwise-valid-looking data - a real
 * gap never has a stray valid-looking magic followed by a broken node, so
 * this distinction is safe in practice. */
static int scan_log(FILE *f, uint64_t image_size, int big_endian, dirent_list *dirents,
                     inode_rec_list *inodes) {
    uint64_t pos = 0;
    while (pos + JFFS2_COMMON_HEADER_SIZE <= image_size) {
        uint8_t hdr[JFFS2_COMMON_HEADER_SIZE];
        if (crimp_fs_seek64(f, pos) != 0 ||
            fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
            return -1;
        }
        if (crimp_fs_decode_u16(hdr, big_endian) != JFFS2_MAGIC) {
            uint64_t next_pos;
            if (find_next_node(f, pos, image_size, big_endian, &next_pos) != 0) {
                break; /* genuinely no more valid nodes: real end of log */
            }
            pos = next_pos;
            continue;
        }
        uint16_t nodetype = crimp_fs_decode_u16(hdr + 2, big_endian);
        uint32_t totlen = crimp_fs_decode_u32(hdr + 4, big_endian);

        /* A node can never be shorter than its own common header, and must
         * fit within the declared image size - reject rather than let a
         * crafted/corrupt totlen drive the scan cursor somewhere absurd. */
        if (totlen < JFFS2_COMMON_HEADER_SIZE || pos + totlen > image_size) {
            return -1;
        }

        if (nodetype == JFFS2_NODETYPE_DIRENT) {
            if (totlen < JFFS2_COMMON_HEADER_SIZE + JFFS2_DIRENT_FIXED_SIZE) {
                return -1;
            }
            uint8_t fixed[JFFS2_DIRENT_FIXED_SIZE];
            if (fread(fixed, 1, sizeof(fixed), f) != sizeof(fixed)) {
                return -1;
            }
            uint32_t pino = crimp_fs_decode_u32(fixed + 0, big_endian);
            uint32_t version = crimp_fs_decode_u32(fixed + 4, big_endian);
            uint32_t ino = crimp_fs_decode_u32(fixed + 8, big_endian);
            uint8_t nsize = fixed[16];
            uint32_t name_len_avail =
                totlen - JFFS2_COMMON_HEADER_SIZE - JFFS2_DIRENT_FIXED_SIZE;
            if (nsize == 0 || nsize > name_len_avail || nsize > 255) {
                return -1;
            }
            char name[256];
            if (fread(name, 1, nsize, f) != nsize) {
                return -1;
            }
            if (dirent_list_add(dirents, pino, version, ino, name, nsize) != 0) {
                return -1;
            }
        } else if (nodetype == JFFS2_NODETYPE_INODE) {
            if (totlen < JFFS2_COMMON_HEADER_SIZE + JFFS2_INODE_FIXED_SIZE) {
                return -1;
            }
            uint8_t fixed[JFFS2_INODE_FIXED_SIZE];
            if (fread(fixed, 1, sizeof(fixed), f) != sizeof(fixed)) {
                return -1;
            }
            jffs2_inode_rec rec;
            rec.ino = crimp_fs_decode_u32(fixed + 0, big_endian);
            rec.version = crimp_fs_decode_u32(fixed + 4, big_endian);
            rec.mode = crimp_fs_decode_u32(fixed + 8, big_endian);
            /* uid(2)@12, gid(2)@14 - not needed for extraction */
            rec.isize = crimp_fs_decode_u32(fixed + 16, big_endian);
            /* atime/mtime/ctime (4 each)@20,24,28 - not needed */
            rec.frag_offset = crimp_fs_decode_u32(fixed + 32, big_endian);
            rec.csize = crimp_fs_decode_u32(fixed + 36, big_endian);
            rec.dsize = crimp_fs_decode_u32(fixed + 40, big_endian);
            rec.compr = fixed[44];
            /* usercompr@45, flags(2)@46, data_crc(4)@48, node_crc(4)@52 - not needed */
            rec.file_offset = pos + JFFS2_COMMON_HEADER_SIZE + JFFS2_INODE_FIXED_SIZE;

            uint32_t data_avail = totlen - JFFS2_COMMON_HEADER_SIZE - JFFS2_INODE_FIXED_SIZE;
            if (rec.csize > data_avail) {
                return -1;
            }
            if (inode_rec_list_add(inodes, &rec) != 0) {
                return -1;
            }
        }
        /* Other node types (cleanmarker, summary, xattr, padding, ...):
         * skip - nothing else needed for extraction correctness, same
         * reasoning squashfs/cramfs already applied to their own
         * not-needed-for-correctness tables (xattr/export tables). */

        uint64_t next = pos + totlen;
        pos = (next + 3) & ~(uint64_t)3; /* nodes are 4-byte aligned on flash */
    }
    return 0;
}

/* Length-aware name comparison - a plain strcmp() would stop at the first
 * embedded NUL byte, making two genuinely different on-disk names (only
 * their pre-NUL prefix in common) compare equal. Ordinary names (the
 * overwhelming common case) behave identically to strcmp(). */
static int dirent_name_cmp(const char *a, size_t alen, const char *b, size_t blen) {
    size_t minlen = alen < blen ? alen : blen;
    int c = memcmp(a, b, minlen);
    if (c != 0) {
        return c;
    }
    if (alen != blen) {
        return alen < blen ? -1 : 1;
    }
    return 0;
}

/* Comparator: groups dirent records by (pino, name), highest version last
 * within each group. */
static int dirent_cmp(const void *a, const void *b) {
    const jffs2_dirent_rec *da = (const jffs2_dirent_rec *)a;
    const jffs2_dirent_rec *db = (const jffs2_dirent_rec *)b;
    if (da->pino != db->pino) {
        return da->pino < db->pino ? -1 : 1;
    }
    int name_cmp = dirent_name_cmp(da->name, da->name_len, db->name, db->name_len);
    if (name_cmp != 0) {
        return name_cmp;
    }
    if (da->version != db->version) {
        return da->version < db->version ? -1 : 1;
    }
    return 0;
}

static int inode_rec_cmp(const void *a, const void *b) {
    const jffs2_inode_rec *ia = (const jffs2_inode_rec *)a;
    const jffs2_inode_rec *ib = (const jffs2_inode_rec *)b;
    if (ia->ino != ib->ino) {
        return ia->ino < ib->ino ? -1 : 1;
    }
    if (ia->version != ib->version) {
        return ia->version < ib->version ? -1 : 1;
    }
    return 0;
}

/* Lower-bound binary search: both dirents and inodes are sorted primarily by
 * (pino) / (ino) respectively, so every record for a given key occupies one
 * contiguous run starting at the index this returns. Without this, every
 * lookup by pino/ino degenerated into a full linear scan of the whole list -
 * O(N) per call, and since a call happens once per directory entry visited
 * (find_inode_meta, extract_regular_file's fragment loop) or once per
 * directory (for_each_live_child's old pre-scan), the full walk of a crafted
 * image with many flat siblings was O(N^2) overall - a real CPU-exhaustion
 * DoS against a tool whose entire job is processing untrusted images (this
 * was also the concrete cause of test_jffs2_mutation_sweep hanging/crawling
 * during an earlier pass at this file, before its true root cause -
 * extract_regular_file's uncapped final_isize allocation - was identified;
 * both had to be fixed). */
static size_t dirent_lower_bound(const dirent_list *dirents, uint32_t pino) {
    size_t lo = 0, hi = dirents->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (dirents->items[mid].pino < pino) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static size_t inode_lower_bound(const inode_rec_list *inodes, uint32_t ino) {
    size_t lo = 0, hi = inodes->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (inodes->items[mid].ino < ino) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/* Finds the highest-version inode record for `ino` (its authoritative
 * mode/isize) - `inodes` must already be sorted by (ino, version). Returns
 * NULL if `ino` has no inode record at all (a malformed image - every real
 * inode must have written its own metadata at least once). */
static const jffs2_inode_rec *find_inode_meta(const inode_rec_list *inodes, uint32_t ino) {
    size_t i = inode_lower_bound(inodes, ino);
    const jffs2_inode_rec *best = NULL;
    while (i < inodes->count && inodes->items[i].ino == ino) {
        best = &inodes->items[i]; /* sorted ascending by version - last match wins */
        i++;
    }
    return best;
}

/* `isize` on a JFFS2_NODETYPE_INODE node is a plain, attacker-controlled
 * 32-bit field with no enforced relationship to how much data actually
 * backs it (a file built entirely from "hole" fragments costs zero bytes in
 * the image but claims real bytes once extracted) - the same "declared size
 * vastly exceeds real content" shape squashfs.c already guards against via
 * its own MAX_EXTRACTED_FILE_SIZE. Confirmed experimentally: a single
 * mutated isize byte drove extract_regular_file's calloc()+fwrite() below to
 * commit several GB of real memory for one file - that unbounded cost,
 * repeated across every mutated byte, is what made
 * test_jffs2_mutation_sweep hang/crawl rather than run in the expected
 * ~60-90s. Unlike squashfs's 64-bit file_size, isize is only ever a
 * uint32_t (already capped just under 4GiB by its own width), so reusing
 * squashfs's 4GiB bound here would reject nothing; JFFS2 targets raw flash
 * chips that are themselves typically well under this size, so 256MiB is
 * still an enormous margin above any real single file on real hardware. */
#define JFFS2_MAX_EXTRACTED_FILE_SIZE (256ull << 20) /* 256MiB */

/* Reconstructs a regular file's content into `out` (opened for writing,
 * already validated to be a safe, non-symlink path) by replaying every
 * inode_rec for `ino` in ascending version order - a later fragment
 * overwrites earlier bytes at its own offset, the same "higher version
 * wins" rule used for dirents. `inodes` must be sorted by (ino, version).
 * `final_isize` bounds the output (from the highest-version record's own
 * isize) - fragments claiming bytes past it are truncated to fit, matching
 * how a real reader treats a stale fragment left over from a since-shrunk
 * file (ftruncate-via-JFFS2_NODETYPE_INODE with isize < a previous
 * fragment's reach). */
static int extract_regular_file(FILE *f, uint32_t ino, uint32_t final_isize,
                                 const inode_rec_list *inodes, const char *disk_path) {
    if (crimp_fs_path_is_symlink(disk_path)) {
        return -1;
    }
    if (final_isize > JFFS2_MAX_EXTRACTED_FILE_SIZE) {
        return -1;
    }
    if (final_isize == 0) {
        FILE *out = fopen(disk_path, "wb"); // NOSONAR - see note on extract_regular_file's caller
        if (!out) {
            return -1;
        }
        fclose(out);
        return 0;
    }

    uint8_t *content = (uint8_t *)calloc(1, final_isize);
    if (!content) {
        return -1;
    }
    uint8_t *comp_buf = NULL;
    size_t comp_cap = 0;
    int ok = 1;

    /* inodes is sorted by (ino, version), so every fragment for `ino` occupies
     * one contiguous run - iterate just that run instead of the whole list
     * (see dirent_lower_bound/inode_lower_bound's comment for why this
     * matters: a full-list scan per file made the whole-image walk O(N^2)). */
    size_t range_start = inode_lower_bound(inodes, ino);
    size_t range_end = range_start;
    while (range_end < inodes->count && inodes->items[range_end].ino == ino) {
        range_end++;
    }

    for (size_t i = range_start; ok && i < range_end; i++) {
        const jffs2_inode_rec *rec = &inodes->items[i];
        if (rec->dsize == 0) {
            continue;
        }
        uint64_t end = (uint64_t)rec->frag_offset + rec->dsize;
        if (rec->frag_offset >= final_isize) {
            continue; /* entirely past the current end of file - a stale fragment */
        }
        uint32_t usable = (end > final_isize) ? (final_isize - rec->frag_offset) : rec->dsize;

        if (rec->compr == JFFS2_COMPR_NONE) {
            if (rec->csize != rec->dsize) {
                ok = 0;
                break;
            }
            if (crimp_fs_seek64(f, rec->file_offset) != 0 ||
                fread(content + rec->frag_offset, 1, usable, f) != usable) {
                ok = 0;
                break;
            }
            if (usable < rec->dsize &&
                crimp_fs_seek64(f, rec->file_offset + usable) != 0) {
                ok = 0;
                break;
            }
        } else if (rec->compr == JFFS2_COMPR_ZLIB) {
            /* dsize (the claimed decompressed size) is a plain on-disk
             * uint32_t with no relationship enforced to csize (the real
             * compressed byte count, already bounded by data_avail in
             * scan_log - it can't exceed the node's own on-disk size). A
             * crafted node can declare a tiny csize but a dsize near
             * UINT32_MAX - a classic zlib decompression-bomb shape - driving
             * the malloc(rec->dsize) below to attempt a multi-GB allocation
             * per node, independent of and before final_isize's own 256MiB
             * cap is ever reached (that cap bounds the whole *file*, not one
             * fragment's decompression buffer). Reject implausible fragments
             * the same way final_isize already is. */
            if (rec->dsize > JFFS2_MAX_EXTRACTED_FILE_SIZE) {
                ok = 0;
                break;
            }
            if (rec->csize > comp_cap) {
                uint8_t *grown = (uint8_t *)realloc(comp_buf, rec->csize);
                if (!grown) {
                    ok = 0;
                    break;
                }
                comp_buf = grown;
                comp_cap = rec->csize;
            }
            uint8_t *decomp_buf = (uint8_t *)malloc(rec->dsize);
            if (!decomp_buf) {
                ok = 0;
                break;
            }
            uLongf out_len = rec->dsize;
            if (crimp_fs_seek64(f, rec->file_offset) != 0 ||
                fread(comp_buf, 1, rec->csize, f) != rec->csize ||
                uncompress(decomp_buf, &out_len, comp_buf, rec->csize) != Z_OK ||
                out_len != rec->dsize) {
                free(decomp_buf);
                ok = 0;
                break;
            }
            memcpy(content + rec->frag_offset, decomp_buf, usable);
            free(decomp_buf);
        } else {
            /* Any other compressor (rtime, lzo, ...): not implemented -
             * real firmware overwhelmingly uses none or zlib (mkfs.jffs2's
             * own default priority order picks zlib over the weaker
             * built-in compressors whenever it actually helps - see
             * SKILL.md). Fail cleanly rather than misparse. */
            ok = 0;
            break;
        }
    }

    free(comp_buf);
    if (!ok) {
        free(content);
        return -1;
    }

    FILE *out = fopen(disk_path, "wb"); // NOSONAR - see note on this function's caller
    if (!out) {
        free(content);
        return -1;
    }
    size_t written = fwrite(content, 1, final_isize, out); // NOSONAR
    fclose(out);
    free(content);
    if (written != final_isize) {
        remove(disk_path);
        return -1;
    }
    return 0;
}

#define MAX_DIR_DEPTH 32 /* same reasoning as squashfs/cramfs's own caps - see SKILL.md */

typedef struct {
    FILE *f;
    const dirent_list *dirents; /* sorted by (pino, name, version) */
    const inode_rec_list *inodes; /* sorted by (ino, version) */
    crimp_fs_entry_list *out;
    const char *output_dir; /* NULL for listing only */
} jffs2_walk_context;

static int walk_directory(jffs2_walk_context *ctx, uint32_t pino, const char *parent_path,
                           int depth);

/* Finds the live (winning) dirents for `pino` - `dirents` is sorted by
 * (pino, name, version ascending), so within a run of equal (pino, name),
 * the last entry is authoritative; `ino == 0` on that winning entry means
 * "deleted", skip it. Calls `visit` for every live child. */
static int for_each_live_child(jffs2_walk_context *ctx, uint32_t pino,
                                int (*visit)(jffs2_walk_context *, const jffs2_dirent_rec *,
                                             const char *, int),
                                const char *parent_path, int depth) {
    const dirent_list *d = ctx->dirents;
    size_t i = dirent_lower_bound(d, pino);
    while (i < d->count && d->items[i].pino == pino) {
        size_t run_end = i + 1;
        while (run_end < d->count && d->items[run_end].pino == pino &&
               dirent_name_cmp(d->items[run_end].name, d->items[run_end].name_len,
                                d->items[i].name, d->items[i].name_len) == 0) {
            run_end++;
        }
        const jffs2_dirent_rec *winner = &d->items[run_end - 1];
        if (winner->ino != 0) {
            if (visit(ctx, winner, parent_path, depth) != 0) {
                return -1;
            }
        }
        i = run_end;
    }
    return 0;
}

static int visit_child(jffs2_walk_context *ctx, const jffs2_dirent_rec *dirent,
                        const char *parent_path, int depth) {
    if (!crimp_fs_path_component_is_safe(dirent->name, dirent->name_len)) {
        return -1;
    }
    const jffs2_inode_rec *meta = find_inode_meta(ctx->inodes, dirent->ino);
    if (!meta) {
        return -1;
    }

    char child_path[1024];
    int n;
    if (parent_path[0] == '\0') {
        n = snprintf(child_path, sizeof(child_path), "%s", dirent->name);
    } else {
        n = snprintf(child_path, sizeof(child_path), "%s/%s", parent_path, dirent->name);
    }
    if (n < 0 || (size_t)n >= sizeof(child_path)) {
        return -1;
    }

    uint32_t filetype = meta->mode & JFFS2_S_IFMT;
    int is_dir = (filetype == JFFS2_S_IFDIR);
    int is_reg = (filetype == JFFS2_S_IFREG);

    if (crimp_fs_entry_list_add(ctx->out, child_path, is_dir, is_dir ? 0 : meta->isize) != 0) {
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
            rc = extract_regular_file(ctx->f, dirent->ino, meta->isize, ctx->inodes, disk_path);
        }
        /* Symlinks and device/fifo/socket entries: listed above, nothing
         * extracted - same choice squashfs.c/cramfs.c already made. */
    }
    if (rc != 0) {
        return -1;
    }

    if (is_dir && walk_directory(ctx, dirent->ino, child_path, depth + 1) != 0) {
        return -1;
    }
    return 0;
}

static int walk_directory(jffs2_walk_context *ctx, uint32_t pino, const char *parent_path,
                           int depth) {
    if (depth > MAX_DIR_DEPTH) {
        return -1;
    }
    return for_each_live_child(ctx, pino, visit_child, parent_path, depth);
}

/* Detects the image's byte order the same way cramfs does (try the magic
 * as given, then byte-swapped) even though the reference `jffs2dump` tool
 * requires an explicit -b/-l flag instead of auto-detecting - a real
 * embedded image still only has one true on-disk byte order, so applying
 * the same detection Crimp already trusts for cramfs is sound. Also
 * returns the whole-image size actually usable (the caller-supplied file
 * size, since JFFS2 has no superblock field declaring it). */
static int detect_endianness(FILE *f, int *out_big_endian) {
    uint8_t magic_bytes[2];
    if (crimp_fs_seek64(f, 0) != 0 || fread(magic_bytes, 1, 2, f) != 2) {
        return -1;
    }
    if (crimp_fs_decode_u16(magic_bytes, 0) == JFFS2_MAGIC) {
        *out_big_endian = 0;
        return 0;
    }
    if (crimp_fs_decode_u16(magic_bytes, 1) == JFFS2_MAGIC) {
        *out_big_endian = 1;
        return 0;
    }
    return -1;
}

static uint64_t file_size(FILE *f) {
    if (crimp_fs_seek64(f, 0) != 0) {
        return 0;
    }
#if defined(_WIN32)
    if (_fseeki64(f, 0, SEEK_END) != 0) {
        return 0;
    }
    int64_t size = _ftelli64(f);
#else
    if (fseeko(f, 0, SEEK_END) != 0) {
        return 0;
    }
    off_t size = ftello(f);
#endif
    return size > 0 ? (uint64_t)size : 0;
}

static int scan_and_sort(const char *path, int *out_big_endian, dirent_list *dirents,
                          inode_rec_list *inodes, FILE **out_f) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    int big_endian;
    if (detect_endianness(f, &big_endian) != 0) {
        fclose(f);
        return -1;
    }
    uint64_t size = file_size(f);
    if (size < JFFS2_COMMON_HEADER_SIZE) {
        fclose(f);
        return -1;
    }
    if (scan_log(f, size, big_endian, dirents, inodes) != 0) {
        fclose(f);
        return -1;
    }
    if (dirents->count > 0) {
        qsort(dirents->items, dirents->count, sizeof(jffs2_dirent_rec), dirent_cmp);
    }
    if (inodes->count > 0) {
        qsort(inodes->items, inodes->count, sizeof(jffs2_inode_rec), inode_rec_cmp);
    }
    *out_big_endian = big_endian;
    *out_f = f;
    return 0;
}

int crimp_jffs2_identify(const char *path, crimp_fs_info *out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    int big_endian;
    int rc = detect_endianness(f, &big_endian);
    uint64_t size = rc == 0 ? file_size(f) : 0;
    fclose(f);
    if (rc != 0) {
        return -1;
    }

    out->type = CRIMP_FS_JFFS2;
    out->inode_count = 0; /* not known without a full log scan; identify() is metadata-only */
    out->block_size = 0;  /* JFFS2 has no fixed block/page size field to report */
    out->compression = 0;
    out->bytes_used = size;
    return 0;
}

const char *crimp_jffs2_compression_name(void) { return "zlib"; }

static int run(const char *path, const char *output_dir, crimp_fs_entry_list *out) {
    crimp_fs_entry_list_init(out);

    dirent_list dirents = {0};
    inode_rec_list inodes = {0};
    int big_endian;
    FILE *f;
    if (scan_and_sort(path, &big_endian, &dirents, &inodes, &f) != 0) {
        dirent_list_free(&dirents);
        free(inodes.items);
        return -1;
    }
    if (output_dir != NULL && crimp_fs_make_directory(output_dir) != 0) {
        fclose(f);
        dirent_list_free(&dirents);
        free(inodes.items);
        crimp_fs_entry_list_free(out);
        return -1;
    }

    jffs2_walk_context ctx = {f, &dirents, &inodes, out, output_dir};
    int rc = walk_directory(&ctx, JFFS2_ROOT_INO, "", 0);

    fclose(f);
    dirent_list_free(&dirents);
    free(inodes.items);
    if (rc != 0) {
        crimp_fs_entry_list_free(out);
        return -1;
    }
    return 0;
}

int crimp_jffs2_list(const char *path, crimp_fs_entry_list *out) { return run(path, NULL, out); }

int crimp_jffs2_extract(const char *path, const char *output_dir, crimp_fs_entry_list *out) {
    return run(path, output_dir, out);
}
