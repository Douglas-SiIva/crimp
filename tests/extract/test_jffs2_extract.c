#include "extract_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FIXTURE_PATH
#error "FIXTURE_PATH must be defined by the build (see CMakeLists.txt)"
#endif
#ifndef OUTPUT_DIR
#error "OUTPUT_DIR must be defined by the build (see CMakeLists.txt)"
#endif

/* Ground truth: this fixture's content is byte-for-byte identical to the
 * source tree it was built from (mkfs.jffs2 is lossless for regular
 * files) - see tests/fixtures/README.md for how it was generated and
 * regenerated. Content and the full entry list (paths/types/sizes)
 * byte-for-byte validated against a much larger real-world image (a real
 * /usr/share/doc tree via WSL, 2541 files) before this small fixture was
 * committed - see .claude/skills/jffs2-extraction/SKILL.md. */
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

typedef struct {
    const char *path;
    int is_dir;
    unsigned long long size;
} expected_entry;

static const expected_entry EXPECTED[] = {
    {"bin", 1, 0},
    {"bin/busybox", 0, sizeof(EXPECTED_BUSYBOX) - 1},
    {"bin/nested", 1, 0},
    {"bin/nested/deep.txt", 0, sizeof(EXPECTED_DEEP) - 1},
    {"bin/bigfile.bin", 0, BIGFILE_SIZE},
    {"etc", 1, 0},
    {"etc/config.txt", 0, sizeof(EXPECTED_CONFIG) - 1},
    {"etc/passwd", 0, sizeof(EXPECTED_PASSWD) - 1},
};
#define EXPECTED_COUNT (sizeof(EXPECTED) / sizeof(EXPECTED[0]))

static int find_expected(const char *path) {
    for (size_t i = 0; i < EXPECTED_COUNT; i++) {
        if (strcmp(EXPECTED[i].path, path) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int check_entry_list(const crimp_fs_entry_list *list) {
    if (list->count != EXPECTED_COUNT) {
        fprintf(stderr, "FAIL: expected %zu entries, got %zu\n", EXPECTED_COUNT, list->count);
        return 0;
    }
    int seen[EXPECTED_COUNT];
    memset(seen, 0, sizeof(seen));
    for (size_t i = 0; i < list->count; i++) {
        int idx = find_expected(list->items[i].path);
        if (idx < 0) {
            fprintf(stderr, "FAIL: unexpected entry '%s'\n", list->items[i].path);
            return 0;
        }
        const expected_entry *e = &EXPECTED[idx];
        if (list->items[i].is_dir != e->is_dir ||
            (unsigned long long)list->items[i].size != e->size) {
            fprintf(stderr,
                    "FAIL: entry '%s' mismatch (is_dir=%d size=%llu, expected is_dir=%d "
                    "size=%llu)\n",
                    list->items[i].path, list->items[i].is_dir,
                    (unsigned long long)list->items[i].size, e->is_dir, e->size);
            return 0;
        }
        seen[idx] = 1;
    }
    for (size_t i = 0; i < EXPECTED_COUNT; i++) {
        if (!seen[i]) {
            fprintf(stderr, "FAIL: expected entry '%s' was not found\n", EXPECTED[i].path);
            return 0;
        }
    }
    return 1;
}

int main(void) {
    crimp_fs_entry_list list;
    if (crimp_jffs2_extract(FIXTURE_PATH, OUTPUT_DIR, &list) != 0) {
        fprintf(stderr, "FAIL: crimp_jffs2_extract failed on %s\n", FIXTURE_PATH);
        return 1;
    }
    int list_ok = check_entry_list(&list);
    crimp_fs_entry_list_free(&list);
    if (!list_ok) {
        return 1;
    }

    int ok = 1;
    ok &= check_file("etc/config.txt", EXPECTED_CONFIG, sizeof(EXPECTED_CONFIG) - 1);
    ok &= check_file("etc/passwd", EXPECTED_PASSWD, sizeof(EXPECTED_PASSWD) - 1);
    ok &= check_file("bin/busybox", EXPECTED_BUSYBOX, sizeof(EXPECTED_BUSYBOX) - 1);
    ok &= check_file("bin/nested/deep.txt", EXPECTED_DEEP, sizeof(EXPECTED_DEEP) - 1);

    /* bigfile.bin: deterministic repeating "0123456789" pattern, 11000
     * bytes, split by mkfs.jffs2 (small -e 0x1000 erase block) into 3
     * separate inode content nodes (4096 + 4096 + 2808) - exercises
     * reconstructing a file's content across multiple fragments, not just
     * the single-fragment case every other file here hits. */
    unsigned char expected_big[BIGFILE_SIZE];
    for (size_t i = 0; i < BIGFILE_SIZE; i++) {
        expected_big[i] = (unsigned char)('0' + (i % 10));
    }
    ok &= check_file("bin/bigfile.bin", expected_big, BIGFILE_SIZE);

    if (!ok) {
        return 1;
    }

    printf("PASS: crimp_jffs2_extract content and entry list match the source tree\n");
    return 0;
}
