#include "extract_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Regression coverage for JFFS2's on-disk-endianness detection - same
 * rationale as cramfs's test_cramfs_endian.c: no big-endian-host tool is
 * conveniently available in this dev environment to generate a real
 * big-endian image, so this hand-builds a small, deliberately big-endian
 * image byte-by-byte instead. Uses an uncompressed (compr=NONE) content
 * node so the fixture doesn't need to link zlib just to construct valid
 * compressed test data. */

#define JFFS2_MAGIC 0x1985u
#define JFFS2_NODETYPE_DIRENT 0xe001u
#define JFFS2_NODETYPE_INODE 0xe002u

static void fw16_be(FILE *f, uint16_t v) {
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    fwrite(b, 1, 2, f);
}
static void fw32_be(FILE *f, uint32_t v) {
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    fwrite(b, 1, 4, f);
}
static void fw8(FILE *f, uint8_t v) { fwrite(&v, 1, 1, f); }

/* Real nodes are 4-byte aligned on disk (confirmed against real
 * mkfs.jffs2 output - see SKILL.md); pads `written` bytes up to the next
 * 4-byte boundary so the *next* node starts where a real reader expects
 * it. Forgetting this padding was a real bug caught while writing this
 * fixture: without it, the reader correctly (per real on-disk alignment)
 * looks for the next node 3 bytes later than this fixture actually placed
 * it, misreads garbage, and the whole image fails to parse - a bug in the
 * test fixture, not the reader, but worth this comment so it isn't
 * reintroduced. */
static void pad_to_4(FILE *f, uint32_t written) {
    uint32_t pad = (4 - (written % 4)) % 4;
    for (uint32_t i = 0; i < pad; i++) {
        fw8(f, 0);
    }
}

#define S_IFREG_ 0x8000u
#define DT_REG_ 8u

/* Builds a minimal valid big-endian JFFS2 image: root directory (implicit,
 * ino 1) containing one regular file "f.bin" with 5 bytes of uncompressed
 * content "hello". Layout: one dirent node (offset 0), one inode node
 * (right after, 4-byte aligned). */
static int build_be_image(const char *path) {
    const char name[] = "f.bin";
    const uint8_t nsize = (uint8_t)(sizeof(name) - 1);
    const char content[] = "hello";
    const uint32_t content_len = (uint32_t)(sizeof(content) - 1);

    const uint32_t dirent_totlen = 12 + 28 + nsize;         /* 45 */
    const uint32_t inode_totlen = 12 + 56 + content_len;    /* 73 */

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }

    /* Dirent node: magic, nodetype, totlen, hdr_crc(unused by this reader,
     * written as 0), pino, version, ino, mctime, nsize, type, unused[2],
     * node_crc(unused), name_crc(unused), name. */
    fw16_be(f, JFFS2_MAGIC);
    fw16_be(f, JFFS2_NODETYPE_DIRENT);
    fw32_be(f, dirent_totlen);
    fw32_be(f, 0); /* hdr_crc */
    fw32_be(f, 1); /* pino: root */
    fw32_be(f, 0); /* version */
    fw32_be(f, 2); /* ino */
    fw32_be(f, 0); /* mctime */
    fw8(f, nsize);
    fw8(f, (uint8_t)DT_REG_);
    fw16_be(f, 0); /* unused */
    fw32_be(f, 0); /* node_crc */
    fw32_be(f, 0); /* name_crc */
    fwrite(name, 1, nsize, f);
    pad_to_4(f, dirent_totlen);

    /* Inode node: magic, nodetype, totlen, hdr_crc, ino, version, mode,
     * uid, gid, isize, atime, mtime, ctime, offset, csize, dsize, compr,
     * usercompr, flags, data_crc, node_crc, data. */
    fw16_be(f, JFFS2_MAGIC);
    fw16_be(f, JFFS2_NODETYPE_INODE);
    fw32_be(f, inode_totlen);
    fw32_be(f, 0); /* hdr_crc */
    fw32_be(f, 2); /* ino */
    fw32_be(f, 1); /* version */
    fw32_be(f, S_IFREG_ | 0644u); /* mode */
    fw16_be(f, 0); /* uid */
    fw16_be(f, 0); /* gid */
    fw32_be(f, content_len); /* isize */
    fw32_be(f, 0); /* atime */
    fw32_be(f, 0); /* mtime */
    fw32_be(f, 0); /* ctime */
    fw32_be(f, 0); /* offset */
    fw32_be(f, content_len); /* csize */
    fw32_be(f, content_len); /* dsize */
    fw8(f, 0);      /* compr = NONE */
    fw8(f, 0);      /* usercompr */
    fw16_be(f, 0);  /* flags */
    fw32_be(f, 0);                  /* data_crc */
    fw32_be(f, 0);                  /* node_crc */
    fwrite(content, 1, content_len, f);

    fclose(f);
    return 0;
}

int main(void) {
    const char *path = "test_fixture_jffs2_be.img";
    if (build_be_image(path) != 0) {
        fprintf(stderr, "FAIL: could not build big-endian fixture\n");
        return 1;
    }

    crimp_fs_info info;
    if (crimp_jffs2_identify(path, &info) != 0) {
        fprintf(stderr, "FAIL: crimp_jffs2_identify failed on a valid big-endian image\n");
        return 1;
    }
    if (info.type != CRIMP_FS_JFFS2) {
        fprintf(stderr, "FAIL: expected CRIMP_FS_JFFS2\n");
        return 1;
    }

    crimp_fs_entry_list list;
    if (crimp_jffs2_list(path, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_jffs2_list failed on a valid big-endian image\n");
        return 1;
    }
    if (list.count != 1 || strcmp(list.items[0].path, "f.bin") != 0 || list.items[0].is_dir ||
        list.items[0].size != 5) {
        fprintf(stderr, "FAIL: unexpected listing (count=%zu)\n", list.count);
        crimp_fs_entry_list_free(&list);
        return 1;
    }
    crimp_fs_entry_list_free(&list);

    const char *out_dir = "jffs2_be_output";
    crimp_fs_entry_list extract_list;
    if (crimp_jffs2_extract(path, out_dir, &extract_list) != 0) {
        fprintf(stderr, "FAIL: crimp_jffs2_extract failed on a valid big-endian image\n");
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
    char buf[16];
    size_t n = fread(buf, 1, sizeof(buf), ef);
    fclose(ef);
    if (n != 5 || memcmp(buf, "hello", 5) != 0) {
        fprintf(stderr, "FAIL: expected content 'hello' (5 bytes), got %zu bytes\n", n);
        return 1;
    }

    printf("PASS: crimp_jffs2_identify/list/extract correctly decode a big-endian image\n");
    return 0;
}
