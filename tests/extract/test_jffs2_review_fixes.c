#include "extract_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

/* Regression coverage for the 3 real bugs found by /code-review high on the
 * initial JFFS2 implementation (issue #8) - each of these fails without its
 * corresponding fix (confirmed manually: revert the fix, rebuild, rerun,
 * observe the FAIL). See src/extract/jffs2.c's comments at the fixed sites
 * for the full reasoning. */

#define JFFS2_MAGIC 0x1985u
#define JFFS2_NODETYPE_DIRENT 0xe001u
#define JFFS2_NODETYPE_INODE 0xe002u
#define S_IFREG_ 0x8000u
#define DT_REG_ 8u

static void fw16(FILE *f, uint16_t v) {
    uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    fwrite(b, 1, 2, f);
}
static void fw32(FILE *f, uint32_t v) {
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    fwrite(b, 1, 4, f);
}
static void fw8(FILE *f, uint8_t v) { fwrite(&v, 1, 1, f); }

/* Real nodes are 4-byte aligned on disk - see test_jffs2_endian.c's
 * pad_to_4 for why this matters (a fixture bug here, not a reader bug,
 * would misdirect the next node's read). */
static void pad_to_4(FILE *f, uint32_t written) {
    uint32_t pad = (4 - (written % 4)) % 4;
    for (uint32_t i = 0; i < pad; i++) {
        fw8(f, 0);
    }
}

static void write_dirent(FILE *f, uint32_t pino, uint32_t version, uint32_t ino,
                          const char *name, size_t name_len) {
    uint32_t totlen = (uint32_t)(12 + 28 + name_len);
    fw16(f, JFFS2_MAGIC);
    fw16(f, JFFS2_NODETYPE_DIRENT);
    fw32(f, totlen);
    fw32(f, 0); /* hdr_crc */
    fw32(f, pino);
    fw32(f, version);
    fw32(f, ino);
    fw32(f, 0); /* mctime */
    fw8(f, (uint8_t)name_len);
    fw8(f, (uint8_t)DT_REG_);
    fw16(f, 0); /* unused */
    fw32(f, 0); /* node_crc */
    fw32(f, 0); /* name_crc */
    fwrite(name, 1, name_len, f);
    pad_to_4(f, totlen);
}

/* Writes an inode node's fixed 56-byte body + `data` (already the on-disk
 * payload - compressed if compr != NONE). `csize`/`dsize` are passed
 * separately from `data_len` so a caller can deliberately lie about them
 * (that's the whole point of the dsize-bomb test below). */
static void write_inode(FILE *f, uint32_t ino, uint32_t version, uint32_t isize,
                         uint32_t frag_offset, uint32_t csize, uint32_t dsize, uint8_t compr,
                         const void *data, size_t data_len) {
    uint32_t totlen = (uint32_t)(12 + 56 + data_len);
    fw16(f, JFFS2_MAGIC);
    fw16(f, JFFS2_NODETYPE_INODE);
    fw32(f, totlen);
    fw32(f, 0); /* hdr_crc */
    fw32(f, ino);
    fw32(f, version);
    fw32(f, S_IFREG_ | 0644u); /* mode */
    fw16(f, 0); /* uid */
    fw16(f, 0); /* gid */
    fw32(f, isize);
    fw32(f, 0); /* atime */
    fw32(f, 0); /* mtime */
    fw32(f, 0); /* ctime */
    fw32(f, frag_offset);
    fw32(f, csize);
    fw32(f, dsize);
    fw8(f, compr);
    fw8(f, 0); /* usercompr */
    fw16(f, 0); /* flags */
    fw32(f, 0); /* data_crc */
    fw32(f, 0); /* node_crc */
    if (data_len > 0) {
        fwrite(data, 1, data_len, f);
    }
    pad_to_4(f, totlen);
}

/* --- Test 1: embedded-NUL dirent name must be rejected, not silently
 * truncated --------------------------------------------------------------
 *
 * visit_child() used to validate a dirent name with strlen(dirent->name)
 * instead of the true on-disk nsize, so a name containing an embedded NUL
 * (e.g. on-disk bytes "evil\0x", nsize=6) passed crimp_fs_path_component_is_
 * safe() as if it were just "evil" (4 bytes, strlen stops at the NUL) - the
 * function's own embedded-NUL check never saw the real length, so it never
 * fired. A real reader must reject this outright, the same way squashfs.c's
 * PR #33 fix already established for this exact class of mistake. */
static int build_embedded_nul_image(const char *path) {
    const char name[] = {'e', 'v', 'i', 'l', '\0', 'x'};
    const size_t name_len = sizeof(name);
    const char content[] = "hi";
    const uint32_t content_len = (uint32_t)(sizeof(content) - 1);

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    write_dirent(f, 1, 1, 2, name, name_len);
    write_inode(f, 2, 1, content_len, 0, content_len, content_len, 0 /* NONE */, content,
                content_len);
    fclose(f);
    return 0;
}

static int test_embedded_nul_rejected(void) {
    const char *path = "jffs2_review_embedded_nul.img";
    if (build_embedded_nul_image(path) != 0) {
        fprintf(stderr, "FAIL: could not build embedded-NUL fixture\n");
        return 0;
    }
    crimp_fs_entry_list list;
    int rc = crimp_jffs2_list(path, &list);
    if (rc == 0) {
        fprintf(stderr,
                "FAIL: crimp_jffs2_list accepted a dirent name with an embedded NUL byte "
                "(count=%zu, first path=%s) - the safety check was bypassed\n",
                list.count, list.count > 0 ? list.items[0].path : "<none>");
        crimp_fs_entry_list_free(&list);
        return 0;
    }
    printf("PASS: embedded-NUL dirent name correctly rejected\n");
    return 1;
}

/* --- Test 2: a single fragment's dsize must be capped independently of
 * final_isize --------------------------------------------------------------
 *
 * extract_regular_file()'s ZLIB branch used to malloc(rec->dsize) - the raw,
 * attacker-controlled on-disk field - before ever clamping to what's
 * actually usable (final_isize - frag_offset). A crafted node can declare a
 * tiny, real, validly-compressed csize but an enormous dsize; the final
 * file's own reported isize can independently be tiny (a later, higher-
 * version metadata-only node can shrink it, same "since-shrunk file"
 * scenario extract_regular_file's own comments already describe) - so the
 * whole-file JFFS2_MAX_EXTRACTED_FILE_SIZE cap on final_isize never sees
 * this, and the fragment's own decompression buffer allocation was
 * completely unbounded.
 *
 * Needs *real* compressed data (not garbage) - garbage csize bytes would
 * make uncompress() itself fail with Z_DATA_ERROR regardless of the fix,
 * which would return -1 either way and prove nothing. All-zero content
 * compresses to a few KB even at ~256MiB, so this stays cheap. */
#define BOMB_DSIZE (257u * 1024u * 1024u) /* just over JFFS2_MAX_EXTRACTED_FILE_SIZE (256MiB) */

static int build_dsize_bomb_image(const char *path) {
    unsigned char *zeros = (unsigned char *)calloc(1, BOMB_DSIZE);
    if (!zeros) {
        fprintf(stderr, "FAIL: could not allocate %u-byte zero buffer for compression\n",
                BOMB_DSIZE);
        return -1;
    }
    uLong bound = compressBound(BOMB_DSIZE);
    unsigned char *compressed = (unsigned char *)malloc(bound);
    if (!compressed) {
        free(zeros);
        fprintf(stderr, "FAIL: could not allocate compression output buffer\n");
        return -1;
    }
    uLongf comp_len = bound;
    int zrc = compress(compressed, &comp_len, zeros, BOMB_DSIZE);
    free(zeros);
    if (zrc != Z_OK) {
        free(compressed);
        fprintf(stderr, "FAIL: compress() failed (rc=%d)\n", zrc);
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        free(compressed);
        return -1;
    }
    /* One dirent -> ino 2. One inode node: isize=10 (the whole *file*'s
     * reported size - well under the cap), but this fragment's own dsize is
     * BOMB_DSIZE - the same node providing both isize and the oversized
     * fragment, no need for a second version to make the point. */
    const char name[] = "f.bin";
    write_dirent(f, 1, 1, 2, name, sizeof(name) - 1);
    write_inode(f, 2, 1, /*isize=*/10, /*frag_offset=*/0, (uint32_t)comp_len, BOMB_DSIZE,
                6 /* ZLIB */, compressed, comp_len);
    fclose(f);
    free(compressed);
    return 0;
}

static void make_scratch_dir(const char *path) {
#if defined(_WIN32)
    _mkdir(path);
#else
    mkdir(path, 0700);
#endif
}

static int test_dsize_bomb_rejected(void) {
    const char *path = "jffs2_review_dsize_bomb.img";
    if (build_dsize_bomb_image(path) != 0) {
        return 0;
    }

    /* Listing never touches fragment content, only the winning inode's own
     * isize (10, legitimate) - it must still succeed. */
    crimp_fs_entry_list list;
    if (crimp_jffs2_list(path, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_jffs2_list unexpectedly failed on a small-isize file\n");
        return 0;
    }
    int list_ok = list.count == 1 && strcmp(list.items[0].path, "f.bin") == 0 &&
                  !list.items[0].is_dir && list.items[0].size == 10;
    crimp_fs_entry_list_free(&list);
    if (!list_ok) {
        fprintf(stderr, "FAIL: unexpected listing for the dsize-bomb fixture\n");
        return 0;
    }

    const char *out_dir = "jffs2_review_dsize_bomb_out";
    make_scratch_dir(out_dir);
    crimp_fs_entry_list extract_list;
    int rc = crimp_jffs2_extract(path, out_dir, &extract_list);
    if (rc == 0) {
        fprintf(stderr,
                "FAIL: crimp_jffs2_extract accepted a %u-byte fragment dsize (over the "
                "256MiB cap) despite final_isize being only 10 bytes\n",
                BOMB_DSIZE);
        crimp_fs_entry_list_free(&extract_list);
        return 0;
    }

    printf("PASS: oversized fragment dsize correctly rejected independent of final_isize\n");
    return 1;
}

/* --- Test 3: a large flat directory must resolve in near-linear time,
 * not quadratic -------------------------------------------------------------
 *
 * find_inode_meta() and for_each_live_child() used to do a full linear scan
 * of the *entire* dirent/inode list on every call - O(N) per directory
 * entry visited, so a flat directory with N siblings drove the whole walk
 * to O(N^2). Both lists are sorted (by (pino,name,version) and
 * (ino,version) respectively) specifically so a bounded binary-search
 * lookup is possible instead - this proves the walk stays fast even at a
 * size where the old O(N^2) behavior would not plausibly finish inside any
 * reasonable test timeout. */
#define FLAT_CHILD_COUNT 150000

static int build_flat_directory_image(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    for (uint32_t i = 0; i < FLAT_CHILD_COUNT; i++) {
        char name[16];
        int n = snprintf(name, sizeof(name), "f%06u", i);
        uint32_t ino = i + 2;
        write_dirent(f, 1, 1, ino, name, (size_t)n);
        write_inode(f, ino, 1, /*isize=*/0, 0, 0, 0, 0 /* NONE */, NULL, 0);
    }
    fclose(f);
    return 0;
}

static int test_flat_directory_perf(void) {
    const char *path = "jffs2_review_flat_dir.img";
    if (build_flat_directory_image(path) != 0) {
        fprintf(stderr, "FAIL: could not build flat-directory fixture\n");
        return 0;
    }

    clock_t start = clock();
    crimp_fs_entry_list list;
    int rc = crimp_jffs2_list(path, &list);
    double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;

    if (rc != 0) {
        fprintf(stderr, "FAIL: crimp_jffs2_list failed on a valid flat-directory image\n");
        return 0;
    }
    size_t count = list.count;
    crimp_fs_entry_list_free(&list);

    if (count != FLAT_CHILD_COUNT) {
        fprintf(stderr, "FAIL: expected %d entries, got %zu\n", FLAT_CHILD_COUNT, count);
        return 0;
    }
    /* Generous bound: the indexed (O(N log N)) walk finishes in well under a
     * second on ordinary hardware; the old O(N^2) linear-scan behavior at
     * this N would need tens of seconds to minutes. */
    if (elapsed > 15.0) {
        fprintf(stderr,
                "FAIL: crimp_jffs2_list took %.2fs for %d flat siblings - looks like an "
                "unindexed O(N^2) scan again\n",
                elapsed, FLAT_CHILD_COUNT);
        return 0;
    }

    printf("PASS: %d flat siblings listed correctly in %.3fs\n", FLAT_CHILD_COUNT, elapsed);
    return 1;
}

int main(void) {
    int ok = 1;
    ok &= test_embedded_nul_rejected();
    ok &= test_dsize_bomb_rejected();
    ok &= test_flat_directory_perf();
    return ok ? 0 : 1;
}
